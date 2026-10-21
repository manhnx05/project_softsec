from pathlib import Path

import yaml

from src.specification.schemas import ProjectSpec, TestScenarioSpec


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
        if file.name == "test_scenarios.yaml" or file.name.startswith("test_"):
            continue
        specs.append(load_yaml(file))

    return specs


def load_test_scenarios(
    path: str | Path | None = None
) -> list[TestScenarioSpec]:
    if path is None:
        path = Path("specs") / "test_scenarios.yaml"
    else:
        path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"Test scenario file not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    raw_scenarios = data.get("scenarios", [])
    return [
        TestScenarioSpec.model_validate(scenario)
        for scenario in raw_scenarios
    ]


def load_raw_test_scenarios(
    path: str | Path | None = None
) -> list[dict[str, object]]:
    if path is None:
        path = Path("specs") / "test_scenarios.yaml"
    else:
        path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"Test scenario file not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    return list(data.get("scenarios", []))