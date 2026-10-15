"""Bounded UTF-8 JSON/YAML parsing with no aliases, merges, tags, or duplicate keys."""

import json
import re
from pathlib import Path

import yaml
from pydantic import BaseModel, ValidationError
from yaml.events import AliasEvent, CollectionEndEvent, CollectionStartEvent, ScalarEvent

from agentsec.contracts.errors import ArtifactValidationError, ErrorCode, ValidationIssue, fail
from agentsec.contracts.models import AgentSecurityContract

MAX_BYTES = 1_048_576
MAX_DEPTH = 64


class StrictLoader(yaml.SafeLoader):
    """No YAML implicit timestamps/bools/numbers: only JSON scalar spelling."""


# Work on a fresh resolver map; never change global SafeLoader behavior.
StrictLoader.yaml_implicit_resolvers = {}
for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items():
    StrictLoader.yaml_implicit_resolvers[first] = [
        (tag, pattern) for tag, pattern in resolvers if tag == "tag:yaml.org,2002:null"
    ]

StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$"), list("tf")
)
StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int", re.compile(r"^-?(?:0|[1-9][0-9]*)$"), list("-0123456789")
)
StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:float",
    re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+(?:[eE][+-]?[0-9]+)?|[eE][+-]?[0-9]+)$"),
    list("-0123456789"),
)


def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if not isinstance(key, str):
            fail(ErrorCode.INVALID_SCHEMA, "Object keys must be strings")
        if key in result:
            fail(ErrorCode.DUPLICATE_KEY, "Duplicate mapping key", key)
        result[key] = value
    return result


def construct_mapping(loader: StrictLoader, node: yaml.MappingNode) -> dict[str, object]:
    pairs = []
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str):
            fail(ErrorCode.INVALID_SCHEMA, "Object keys must be strings")
        if key == "<<":
            fail(ErrorCode.UNSAFE_YAML, "YAML merge keys are forbidden")
        pairs.append((key, loader.construct_object(value_node, deep=True)))
    return unique_pairs(pairs)


StrictLoader.add_constructor("tag:yaml.org,2002:map", construct_mapping)


def reject_constant(value: str) -> None:
    fail(ErrorCode.INVALID_SCHEMA, "Non-finite JSON number")


def check_tree(value: object, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        fail(ErrorCode.INPUT_TOO_DEEP, "Document nesting exceeds limit")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                fail(ErrorCode.INVALID_SCHEMA, "Object keys must be strings")
            check_tree(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            check_tree(child, depth + 1)


def parse_document(text: str, *, format: str = "yaml") -> object:
    if len(text.encode("utf-8")) > MAX_BYTES:
        fail(ErrorCode.INPUT_TOO_LARGE, "Document exceeds 1 MiB")
    try:
        if format == "json":
            value = json.loads(text, object_pairs_hook=unique_pairs, parse_constant=reject_constant)
        elif format == "yaml":
            depth = 0
            for event in yaml.parse(text):
                if isinstance(event, AliasEvent) or getattr(event, "anchor", None) is not None:
                    fail(ErrorCode.UNSAFE_YAML, "YAML anchors/aliases are forbidden")
                if isinstance(event, (ScalarEvent, CollectionStartEvent)) and event.tag is not None:
                    fail(ErrorCode.UNSAFE_YAML, "Explicit YAML tags are forbidden")
                if isinstance(event, CollectionStartEvent):
                    depth += 1
                    if depth > MAX_DEPTH:
                        fail(ErrorCode.INPUT_TOO_DEEP, "Document nesting exceeds limit")
                elif isinstance(event, CollectionEndEvent):
                    depth -= 1
            value = yaml.load(text, Loader=StrictLoader)
        else:
            fail(ErrorCode.INVALID_SCHEMA, "Supported formats: yaml, json")
        check_tree(value)
        return value
    except RecursionError:
        fail(ErrorCode.INPUT_TOO_DEEP, "Document nesting exceeds parser limits")
    except (yaml.YAMLError, json.JSONDecodeError, ValueError):
        fail(ErrorCode.INVALID_SCHEMA, "Malformed document")


def validate_data[ModelT: BaseModel](model: type[ModelT], value: object) -> ModelT:
    """Use strict JSON wire semantics consistently for YAML, JSON, and callers."""
    check_tree(value)
    try:
        encoded = json.dumps(value, allow_nan=False)
        return model.model_validate_json(encoded)
    except ValidationError as exc:
        issues = []
        for error in exc.errors(include_input=False, include_url=False):
            kind = error["type"]
            loc = ".".join(str(p) for p in error["loc"])
            if kind in ErrorCode._value2member_map_:
                code = ErrorCode(kind)
            elif kind == "extra_forbidden":
                code = ErrorCode.UNKNOWN_FIELD
            elif "schema_version" in error["loc"]:
                code = ErrorCode.UNSUPPORTED_SCHEMA_VERSION
            elif "budgets" in error["loc"]:
                code = ErrorCode.INVALID_BUDGET
            elif "default_timeout_seconds" in error["loc"]:
                code = ErrorCode.INVALID_TIMEOUT
            elif kind == "union_tag_invalid" and any(
                part in {"assertions", "utility_assertions"} for part in error["loc"]
            ):
                code = ErrorCode.UNKNOWN_ASSERTION_TYPE
            elif kind == "string_pattern_mismatch":
                code = (
                    ErrorCode.INVALID_CAPABILITY
                    if "capabilit" in loc
                    else ErrorCode.INVALID_IDENTIFIER
                )
            else:
                code = ErrorCode.INVALID_SCHEMA
            issues.append(ValidationIssue(code=code, message=error["msg"], path=loc))
        raise ArtifactValidationError(issues) from exc
    except (TypeError, ValueError):
        fail(ErrorCode.INVALID_SCHEMA, "Document must contain finite JSON values")
    raise AssertionError("Unreachable")


def load_artifact[ModelT: BaseModel](path: Path, model: type[ModelT]) -> ModelT:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            fail(ErrorCode.INPUT_TOO_LARGE, "Document exceeds 1 MiB")
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise ArtifactValidationError(
            [
                ValidationIssue(
                    code=ErrorCode.PATH_ERROR, message="Cannot read UTF-8 artifact", path=str(path)
                )
            ]
        ) from exc
    if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
        fail(ErrorCode.INVALID_SCHEMA, "Expected .json, .yaml, or .yml", str(path))
    return validate_data(
        model, parse_document(text, format="json" if path.suffix.lower() == ".json" else "yaml")
    )


def load_contract(path: Path) -> AgentSecurityContract:
    return load_artifact(path, AgentSecurityContract)


def load_contracts(paths: list[Path]) -> tuple[AgentSecurityContract, ...]:
    contracts = tuple(load_contract(p) for p in paths)
    ids = [c.metadata.contract_id for c in contracts]
    if len(ids) != len(set(ids)):
        fail(ErrorCode.DUPLICATE_ID, "Duplicate contract ID in loaded set")
    return contracts
