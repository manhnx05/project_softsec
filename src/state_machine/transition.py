from dataclasses import dataclass


@dataclass
class Transition:
    source: str
    target: str
    event: str
    guard: str | None = None

    def __str__(self) -> str:
        return (
            f"{self.source} "
            f"--[{self.event}]--> "
            f"{self.target}"
        )