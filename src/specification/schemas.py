from pydantic import BaseModel, Field


class ParameterSpec(BaseModel):
    name: str
    type: str
    default: object | None = None
    description: str = ""


class StateSpec(BaseModel):
    name: str
    description: str = ""


class TransitionSpec(BaseModel):
    source: str
    target: str
    event: str
    guard: str | None = None


class ConstraintSpec(BaseModel):
    name: str
    expression: str
    description: str = ""


class FunctionSpec(BaseModel):
    name: str
    description: str = ""

    parameters: list[ParameterSpec] = Field(default_factory=list)

    states: list[StateSpec] = Field(default_factory=list)

    transitions: list[TransitionSpec] = Field(
        default_factory=list
    )

    constraints: list[ConstraintSpec] = Field(
        default_factory=list
    )


class ProjectSpec(BaseModel):
    project_name: str
    version: str = "1.0"

    functions: list[FunctionSpec] = Field(
        default_factory=list
    )