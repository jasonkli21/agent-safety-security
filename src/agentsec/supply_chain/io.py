"""Safe bounded JSON ingress with duplicate/depth rejection and minimized diagnostics."""

import json
from pathlib import Path

from pydantic import BaseModel, ValidationError

from agentsec.runtime.models import RuntimeFailure
from agentsec.supply_chain.inspection import read_local


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def load_json[M: BaseModel](path: Path, model: type[M]) -> M:
    try:
        raw = read_local(path.absolute()).decode("utf-8")
        # Bound nesting before the decoder or Pydantic sees recursive material.
        depth = 0
        quoted = escaped = False
        for ch in raw:
            if quoted:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    quoted = False
            elif ch == '"':
                quoted = True
            elif ch in "[{":
                depth += 1
                if depth > 64:
                    raise ValueError
            elif ch in "]}":
                depth -= 1
        json.loads(raw, object_pairs_hook=_pairs)
        return model.model_validate_json(raw)
    except (ValueError, ValidationError, RecursionError) as exc:
        raise RuntimeFailure("TRUST_INPUT_INVALID") from exc
