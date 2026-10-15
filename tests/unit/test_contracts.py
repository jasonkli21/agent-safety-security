import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from agentsec.contracts.canonical import canonical_contract, document_hash, effective_policy_hash
from agentsec.contracts.errors import ArtifactValidationError, ErrorCode
from agentsec.contracts.loader import load_artifact, load_contract, load_contracts, validate_data
from agentsec.contracts.models import AgentSecurityContract
from agentsec.domain.serialization import canonical_json, content_digest

ROOT = Path(__file__).resolve().parents[2]
VALID = ROOT / "examples/contracts/research.yaml"


def authored():
    return yaml.safe_load(VALID.read_text())


@pytest.mark.parametrize("path", sorted((ROOT / "examples/contracts").glob("*.yaml")))
def test_contract_round_trip(path):
    contract = load_contract(path)
    assert load_contract(path) == validate_data(
        AgentSecurityContract, json.loads(canonical_contract(contract))
    )
    assert document_hash(contract).startswith("sha256:")


INVALID = {
    "unknown-field": ErrorCode.UNKNOWN_FIELD,
    "unsupported-version": ErrorCode.UNSUPPORTED_SCHEMA_VERSION,
    "unquoted-version": ErrorCode.UNSUPPORTED_SCHEMA_VERSION,
    "duplicate-rule-id": ErrorCode.DUPLICATE_RULE_ID,
    "contradictory-rule": ErrorCode.CONTRADICTORY_RULE,
    "duplicate-rule": ErrorCode.DUPLICATE_RULE,
    "negative-budget": ErrorCode.INVALID_BUDGET,
    "string-budget": ErrorCode.INVALID_BUDGET,
    "boolean-budget": ErrorCode.INVALID_BUDGET,
    "invalid-timeout": ErrorCode.INVALID_TIMEOUT,
    "invalid-capability": ErrorCode.INVALID_CAPABILITY,
    "invalid-decision": ErrorCode.INVALID_SCHEMA,
    "invalid-identifier": ErrorCode.INVALID_IDENTIFIER,
    "data-overlap": ErrorCode.CONTRADICTORY_RULE,
    "duplicate-invariant": ErrorCode.DUPLICATE_ID,
    "environment-mismatch": ErrorCode.INVALID_SCHEMA,
    "unsafe": ErrorCode.UNSAFE_YAML,
    "alias": ErrorCode.UNSAFE_YAML,
    "duplicate-key": ErrorCode.DUPLICATE_KEY,
}


@pytest.mark.parametrize("name,code", INVALID.items())
def test_invalid_contract_corpus(name, code):
    with pytest.raises(ArtifactValidationError) as caught:
        load_contract(ROOT / f"tests/fixtures/contracts/{name}.yaml")
    assert code in {i.code for i in caught.value.issues}
    assert caught.value.issues[0].model_dump(mode="json")["code"]


def test_duplicate_contract_set():
    with pytest.raises(ArtifactValidationError) as caught:
        load_contracts([VALID, VALID])
    assert caught.value.issues[0].code == ErrorCode.DUPLICATE_ID


@pytest.mark.parametrize(
    "field",
    [
        "max_model_calls",
        "max_tool_calls",
        "max_external_writes",
        "max_destructive_calls",
        "max_runtime_seconds",
        "max_cost_usd",
        "max_delegated_agents",
    ],
)
@pytest.mark.parametrize("bad", [-1, "3", True])
def test_strict_budgets(field, bad):
    data = authored()
    data["budgets"][field] = bad
    with pytest.raises(ArtifactValidationError):
        validate_data(AgentSecurityContract, data)


def test_zero_budgets_and_positive_timeout():
    data = authored()
    data["budgets"] = {"max_tool_calls": 0, "max_cost_usd": 0}
    assert validate_data(AgentSecurityContract, data).budgets.max_tool_calls == 0


@pytest.mark.parametrize("bad", [False, "120", -1, 0, 1.5])
def test_strict_timeout(bad):
    data = authored()
    data["approvals"]["default_timeout_seconds"] = bad
    with pytest.raises(ArtifactValidationError):
        validate_data(AgentSecurityContract, data)


def test_order_independence():
    a = authored()
    b = deepcopy(a)
    b["tools"]["rules"].reverse()
    b["task_scope"]["requested_capabilities"].reverse()
    b = dict(reversed(list(b.items())))
    ma, mb = (validate_data(AgentSecurityContract, d) for d in (a, b))
    assert canonical_contract(ma) == canonical_contract(mb)
    assert document_hash(ma) == document_hash(mb)
    assert effective_policy_hash(ma) == effective_policy_hash(mb)


def test_cosmetic_description_and_context():
    a = authored()
    b = deepcopy(a)
    b["metadata"]["description"] = "New documentation"
    b["agent"]["name"] = "Friendly display name"
    b["agent"]["model_name"] = "example-model"
    ma, mb = (validate_data(AgentSecurityContract, d) for d in (a, b))
    assert document_hash(ma) != document_hash(mb)
    assert effective_policy_hash(ma) == effective_policy_hash(mb)


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["budgets"].update(max_tool_calls=21),
        lambda d: d["identity"]["principal"].update(principal_id="agent:other"),
        lambda d: d["data"]["rules"][0].update(denied_destinations=["internal"]),
        lambda d: d["tools"]["rules"][0].update(decision="DENY"),
        lambda d: d["task_scope"].update(requested_capabilities=[]),
        lambda d: d["approvals"].update(default_timeout_seconds=121),
        lambda d: d["invariants"][0].update(description="Different security intent"),
    ],
)
def test_security_changes_affect_both_hashes(change):
    data = authored()
    before = validate_data(AgentSecurityContract, data)
    change(data)
    after = validate_data(AgentSecurityContract, data)
    assert document_hash(before) != document_hash(after)
    assert effective_policy_hash(before) != effective_policy_hash(after)


def test_agent_trust_context_is_opaque_and_security_relevant():
    data = authored()
    data["agent"]["trust_level"] = None
    without_tier = validate_data(AgentSecurityContract, data)
    data["agent"]["trust_level"] = "tier:reviewed"
    with_tier = validate_data(AgentSecurityContract, data)
    assert document_hash(without_tier) != document_hash(with_tier)
    assert effective_policy_hash(without_tier) != effective_policy_hash(with_tier)


def test_unspecified_and_empty_task_scope_are_distinct():
    data = authored()
    data["task_scope"]["requested_capabilities"] = None
    unspecified = validate_data(AgentSecurityContract, data)
    data["task_scope"]["requested_capabilities"] = []
    empty = validate_data(AgentSecurityContract, data)
    assert effective_policy_hash(unspecified) != effective_policy_hash(empty)


def test_data_and_invariant_ordering():
    data = authored()
    data["data"]["rules"].append({"rule_id": "secret-rule", "label": "SECRET"})
    data["invariants"].append({"id": "second", "description": "Another intent"})
    before = validate_data(AgentSecurityContract, data)
    data["data"]["rules"].reverse()
    data["invariants"].reverse()
    after = validate_data(AgentSecurityContract, data)
    assert document_hash(before) == document_hash(after)
    assert effective_policy_hash(before) == effective_policy_hash(after)


@pytest.mark.parametrize(
    "change,code",
    [
        (
            lambda d: d["data"]["rules"].append(deepcopy(d["data"]["rules"][0])),
            ErrorCode.DUPLICATE_RULE,
        ),
        (
            lambda d: d["data"]["rules"][0].update(rule_id=d["tools"]["rules"][0]["rule_id"]),
            ErrorCode.DUPLICATE_RULE_ID,
        ),
        (
            lambda d: d["data"]["rules"][0].update(allowed_capabilities=["email.send"]),
            ErrorCode.CONTRADICTORY_RULE,
        ),
    ],
)
def test_cross_section_rule_validation(change, code):
    data = authored()
    change(data)
    with pytest.raises(ArtifactValidationError) as caught:
        validate_data(AgentSecurityContract, data)
    assert code in {i.code for i in caught.value.issues}


@given(
    st.dictionaries(st.text(alphabet="abcxyz", min_size=1, max_size=8), st.integers(), max_size=20)
)
def test_map_order_property(mapping):
    assert content_digest(mapping) == content_digest(dict(reversed(list(mapping.items()))))


@given(st.permutations(["web.search", "web.fetch", "email.send"]))
def test_capability_set_order_property(capabilities):
    data = authored()
    data["task_scope"]["requested_capabilities"] = list(capabilities)
    model = validate_data(AgentSecurityContract, data)
    data["task_scope"]["requested_capabilities"] = sorted(capabilities)
    other = validate_data(AgentSecurityContract, data)
    assert document_hash(model) == document_hash(other)
    assert effective_policy_hash(model) == effective_policy_hash(other)


def test_arrays_are_order_sensitive():
    assert canonical_json([1, 2]) != canonical_json([2, 1])


def test_load_generic_contract():
    assert load_artifact(VALID, AgentSecurityContract) == load_contract(VALID)
