"""Shared native Tool call contract and caller-owned authorization result."""
from dataclasses import dataclass
from typing import Awaitable, Callable, Literal

from pydantic import JsonValue

@dataclass(frozen=True)
class Authorization:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class ExecutionPort:
    description: str
    kind: Literal["tool"]
    provenance: Literal["new_observation", "existing_material"]
    permission_description: str
    prepare: Callable[[dict, dict], JsonValue]  # Tool arguments and assigned task.
    invoke: Callable[[JsonValue], Awaitable[JsonValue]]
