from dataclasses import dataclass, field


@dataclass
class State:
    name: str
    description: str = ""
    properties: dict = field(default_factory=dict)

    def __str__(self) -> str:
        return self.name