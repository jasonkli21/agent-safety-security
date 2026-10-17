"""Strict provider JSON shapes; model metadata never supplies protected authority."""

import json
from typing import Literal

from pydantic import JsonValue

from agentsec.runtime.bindings import ProtectedCall
from agentsec.runtime.models import RuntimeFailure, ToolResponse

Provider = Literal["openai", "anthropic", "gemini"]


def _object(
    value: JsonValue, required: set[str], optional: set[str] | frozenset[str] = frozenset()
) -> dict[str, JsonValue]:
    if (
        not isinstance(value, dict)
        or not required <= value.keys()
        or value.keys() - required - optional
    ):
        raise RuntimeFailure("INVALID_PROVIDER_CALL")
    return value


def _pairs(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key")
        result[key] = value
    return result


class ProviderTools:
    def __init__(self, provider: Provider, tools: tuple[ProtectedCall, ...]) -> None:
        if provider not in {"openai", "anthropic", "gemini"}:
            raise RuntimeFailure("UNKNOWN_PROVIDER")
        self.__provider = provider
        self.__tools = {t.tool.descriptor.name: t.for_adapter(provider + "_tools") for t in tools}
        if len(self.__tools) != len(tools):
            raise RuntimeFailure("DUPLICATE_TOOL")

    @property
    def provider(self) -> Provider:
        return self.__provider

    def declarations(self) -> list[dict[str, JsonValue]]:
        result: list[dict[str, JsonValue]] = []
        for call in self.__tools.values():
            d = call.tool.descriptor
            if self.provider == "openai":
                result.append(
                    {
                        "type": "function",
                        "function": {
                            "name": d.name,
                            "description": d.description,
                            "parameters": d.input_schema,
                        },
                    }
                )
            elif self.provider == "anthropic":
                result.append(
                    {"name": d.name, "description": d.description, "input_schema": d.input_schema}
                )
            else:
                result.append(
                    {"name": d.name, "description": d.description, "parameters": d.input_schema}
                )
        return result

    async def invoke(self, value: dict[str, JsonValue]) -> ToolResponse:
        if self.provider == "openai":
            obj = _object(value, {"type", "function"}, {"id"})
            if obj["type"] != "function":
                raise RuntimeFailure("INVALID_PROVIDER_CALL")
            if "id" in obj and not isinstance(obj["id"], str):
                raise RuntimeFailure("INVALID_PROVIDER_CALL")
            f = _object(obj["function"], {"name", "arguments"})
            raw = f["arguments"]
            if not isinstance(raw, str) or len(raw.encode()) > 1_048_576:
                raise RuntimeFailure("INVALID_PROVIDER_CALL")
            try:
                args = json.loads(
                    raw,
                    object_pairs_hook=_pairs,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
                )
            except (ValueError, RecursionError) as exc:
                raise RuntimeFailure("INVALID_PROVIDER_CALL") from exc
            name = f["name"]
        elif self.provider == "anthropic":
            obj = _object(value, {"type", "name", "input", "id"})
            if obj["type"] != "tool_use" or not isinstance(obj["id"], str):
                raise RuntimeFailure("INVALID_PROVIDER_CALL")
            name, args = obj["name"], obj["input"]
        else:
            obj = _object(value, {"name", "args"})
            name, args = obj["name"], obj["args"]
        if not isinstance(name, str) or not isinstance(args, dict):
            raise RuntimeFailure("INVALID_PROVIDER_CALL")
        if name not in self.__tools:
            raise RuntimeFailure("UNKNOWN_TOOL")
        return await self.__tools[name].invoke(args)
