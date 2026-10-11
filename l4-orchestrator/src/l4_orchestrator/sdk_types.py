"""The agreed manager/executor wire contract, independent of the legacy flow."""
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SDKModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class WorkScope(SDKModel):
    target_refs: list[str]
    allowed_tools: list[str]
    restrictions: list[str]


class WorkPlan(SDKModel):
    id: str = Field(pattern=r"^W[1-9][0-9]*$")
    title: str = Field(min_length=1)
    question: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    scope: WorkScope


class ToolExecution(SDKModel):
    kind: Literal["tool"]
    name: str
    arguments_json: str


class AgentExecution(SDKModel):
    kind: Literal["agent"]
    instruction: str
    allowed_tools: list[str]
    input_refs: list[str]


class TaskPlan(SDKModel):
    id: str = Field(pattern=r"^T[1-9][0-9]*$")
    work_id: str = Field(pattern=r"^W[1-9][0-9]*$")
    title: str = Field(min_length=1)
    after: list[str]
    execution: ToolExecution | AgentExecution


class Finding(SDKModel):
    statement: str
    refs: list[str]


class ExecutionReport(SDKModel):
    summary: str
    findings: list[Finding]
    limits: list[str]


class WorkAnswer(SDKModel):
    work_id: str
    answer: str
    refs: list[str]


class ReviewAfter(SDKModel):
    tasks: list[str]
    when: Literal["all", "any"]


class ManagerTurn(SDKModel):
    summary: str
    new_works: list[WorkPlan]
    tasks: list[TaskPlan]
    review_after: ReviewAfter | None
    work_answers: list[WorkAnswer]
    finish: ExecutionReport | None


class FinalManagerTurn(ManagerTurn):
    """The same wire shape, constrained to judgment after the execution budget."""
    new_works: list[WorkPlan] = Field(max_length=0)
    tasks: list[TaskPlan] = Field(max_length=0)
    review_after: None
    finish: ExecutionReport


@dataclass(frozen=True)
class ManagerRunContext:
    job_id: str
    manager_call_id: str


@dataclass(frozen=True)
class ExecutorRunContext:
    job_id: str
    work_id: str
    task_id: str


@dataclass(frozen=True)
class ExecutionLimits:
    """Caller-selected bounds. None disables that bound; no experiment values here."""
    manager_input_bytes: int | None
    manager_calls: int
    runner_turns: int
    task_seconds: float | None
    analysis_seconds: float | None

    def __post_init__(self):
        for name in ("manager_input_bytes", "manager_calls", "runner_turns"):
            value = getattr(self, name)
            if value is None and name == "manager_input_bytes":
                continue
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name in ("task_seconds", "analysis_seconds"):
            value = getattr(self, name)
            if value is not None and (type(value) not in (int, float) or not 0 < value < float("inf")):
                raise ValueError(f"{name} must be finite and positive or None")
