from pathlib import Path

import pytest

from agentsec.contracts.errors import ArtifactValidationError, ErrorCode
from agentsec.contracts.loader import MAX_BYTES, load_contract, parse_document, validate_data
from agentsec.contracts.models import AgentSecurityContract


@pytest.mark.parametrize(
    "text,format,code",
    [
        ('{"schema_version":"0.1","schema_version":"99"}', "json", ErrorCode.DUPLICATE_KEY),
        ('{"a":{"x":1,"x":2}}', "json", ErrorCode.DUPLICATE_KEY),
        ("x: {a: 1, a: 2}", "yaml", ErrorCode.DUPLICATE_KEY),
        ("x: &anchor value", "yaml", ErrorCode.UNSAFE_YAML),
        ("x: !!str 123", "yaml", ErrorCode.UNSAFE_YAML),
        ("x: {<<: {a: 1}}", "yaml", ErrorCode.UNSAFE_YAML),
        ("{true: value}", "yaml", ErrorCode.INVALID_SCHEMA),
        ('{"x":NaN}', "json", ErrorCode.INVALID_SCHEMA),
        ('{"x":Infinity}', "json", ErrorCode.INVALID_SCHEMA),
        ("{", "json", ErrorCode.INVALID_SCHEMA),
        ("[a", "yaml", ErrorCode.INVALID_SCHEMA),
        ("---\nx: 1\n---\nx: 2", "yaml", ErrorCode.INVALID_SCHEMA),
        ("{}", "toml", ErrorCode.INVALID_SCHEMA),
        ("x" * (MAX_BYTES + 1), "yaml", ErrorCode.INPUT_TOO_LARGE),
        ("[" * 70 + "0" + "]" * 70, "yaml", ErrorCode.INPUT_TOO_DEEP),
        ("[" * 70 + "0" + "]" * 70, "json", ErrorCode.INPUT_TOO_DEEP),
        ("[" * 2000 + "0" + "]" * 2000, "json", ErrorCode.INPUT_TOO_DEEP),
    ],
)
def test_parser_rejections(text, format, code):
    with pytest.raises(ArtifactValidationError) as caught:
        parse_document(text, format=format)
    assert caught.value.issues[0].code == code


@pytest.mark.parametrize("value", [[], None, "ALLOW", True, 1, {"schema_version": "0.1"}])
def test_invalid_roots(value):
    with pytest.raises(ArtifactValidationError):
        validate_data(AgentSecurityContract, value)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), object(), {"x": object()}])
def test_non_json_values(value):
    with pytest.raises(ArtifactValidationError):
        validate_data(AgentSecurityContract, value)


@pytest.mark.parametrize(
    "name", ["missing.yaml", "invalid-utf8.yaml", "large.yaml", "wrong.txt", "directory.yaml"]
)
def test_path_errors(tmp_path, name):
    p = tmp_path / name
    expected = ErrorCode.PATH_ERROR
    if name == "invalid-utf8.yaml":
        p.write_bytes(b"\xff")
    elif name == "large.yaml":
        p.write_bytes(b"x" * (MAX_BYTES + 1))
        expected = ErrorCode.INPUT_TOO_LARGE
    elif name == "wrong.txt":
        p.write_text("{}")
        expected = ErrorCode.INVALID_SCHEMA
    elif name == "directory.yaml":
        p.mkdir()
    with pytest.raises(ArtifactValidationError) as caught:
        load_contract(p)
    assert caught.value.issues[0].code == expected


def test_yaml_json_scalar_semantics():
    result = parse_document('a: yes\nb: off\nc: false\nd: 03\ne: 2026-10-15\nf: 1e3\ng: "false"')
    assert result == {
        "a": "yes",
        "b": "off",
        "c": False,
        "d": "03",
        "e": "2026-10-15",
        "f": 1000.0,
        "g": "false",
    }


def test_unsafe_yaml_never_executes():
    sentinel = Path("/private/tmp/agentsec-unsafe-executed")
    assert not sentinel.exists()
    with pytest.raises(ArtifactValidationError):
        parse_document('!!python/object/apply:os.system ["touch /tmp/agentsec-unsafe-executed"]')
    assert not sentinel.exists()


def test_merge_like_content_is_plain_text():
    assert parse_document('content: "<<"') == {"content": "<<"}
