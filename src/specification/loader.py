from pathlib import Path

import yaml

from src.specification.schemas import ProjectSpec


def load_yaml(path: str | Path) -> ProjectSpec:
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"Specification file not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    return ProjectSpec.model_validate(data)


def load_project_spec(directory: str | Path) -> list[ProjectSpec]:
    directory = Path(directory)

    if not directory.exists():
        raise FileNotFoundError(
            f"Specification directory not found: {directory}"
        )

    specs = []

    for file in sorted(directory.glob("*.yaml")):
        specs.append(load_yaml(file))

    return specs