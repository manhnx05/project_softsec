"""Generate Python state enums from Kripke models, then verify the output."""

from __future__ import annotations

import importlib.util
import re
import shutil
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

from jinja2 import (
    Environment,
    FileSystemLoader,
)

from src.kripke.model import KripkeModel
from src.specification.schemas import FunctionSpec

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAFE_C_SOURCES = (
    ("safe", "buffer_copy.c"),
    ("include", "buffer_copy.h"),
)

HEADER = """# ====================================================
# AUTO-GENERATED FILE
# Do not edit manually.
# Generated from Kripke models.
# ====================================================

from enum import Enum


"""


def state_enum_class_name(function_name: str) -> str:
    """Return the Enum class name generated for a function."""
    normalized = re.sub(r"[^0-9a-zA-Z]+", " ", function_name).split()
    return "".join(part[:1].upper() + part[1:] for part in normalized) + "State"


def state_enum_file_name(function_name: str) -> str:
    """Return the module file name generated for a function."""
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", function_name).lower()
    snake = re.sub(r"[^0-9a-z]+", "_", snake).strip("_")
    return f"{snake or 'function'}_states.py"


class CodeGenerator:

    def __init__(self):
        template_dir = Path(__file__).parent / "templates"
        self.environment = Environment(
            loader=FileSystemLoader(template_dir),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def render_states(
        self,
        class_name: str,
        state_names: list[str],
    ) -> str:
        template = self.environment.get_template("state.py.j2")
        return template.render(
            class_name=class_name,
            states=[
                SimpleNamespace(name=name) for name in state_names
            ],
        )

    def generate_states(
        self,
        models: Mapping[str, KripkeModel],
        output: str | Path,
    ) -> Path:
        """Write one ``str`` Enum per model into a single module."""
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        chunks = [HEADER]
        for class_name, model in models.items():
            chunks.append(
                self.render_states(
                    class_name,
                    list(model.states.keys()),
                )
            )

        output_path.write_text(
            "".join(chunks),
            encoding="utf-8",
        )
        return output_path

    def generate_state_enum(
        self,
        function: FunctionSpec,
        output: str | Path = "generated",
    ) -> Path:
        """Write one ``str`` Enum module for a single function spec."""
        output_path = Path(output) / state_enum_file_name(function.name)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(
            HEADER
            + self.render_states(
                state_enum_class_name(function.name),
                [state.name for state in function.states],
            ),
            encoding="utf-8",
        )
        return output_path

    def generate_safe_c_files(
        self,
        output: str | Path = "generated",
    ) -> list[Path]:
        """Copy the canonical safe C implementation and header into ``output``."""
        output_dir = Path(output)
        output_dir.mkdir(parents=True, exist_ok=True)

        generated: list[Path] = []
        for relative_dir, file_name in SAFE_C_SOURCES:
            source = PROJECT_ROOT / "csrc" / relative_dir / file_name
            destination = output_dir / file_name
            shutil.copyfile(source, destination)
            generated.append(destination)
        return generated


def generate_states(
    models: Mapping[str, KripkeModel],
    output: str | Path,
) -> Path:
    """Generate the state module for the given Kripke models."""
    return CodeGenerator().generate_states(models, output)


def verify_generated_module(
    path: str | Path,
    expected: Mapping[str, list[str]],
) -> list[str]:
    """Import the generated module and check every enum matches ``expected``.

    Returns a list of error messages; an empty list means the generated code
    loaded and exposes exactly the expected enum members.
    """
    path = Path(path)
    if not path.exists():
        return [f"Generated module not found: {path}"]

    spec = importlib.util.spec_from_file_location(
        "generated_states",
        path,
    )
    if spec is None or spec.loader is None:
        return [f"Could not load generated module: {path}"]

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001 - report any import-time failure
        return [f"Generated module failed to import: {exc!r}"]

    errors: list[str] = []
    for class_name, state_names in expected.items():
        enum_class = getattr(module, class_name, None)
        if enum_class is None:
            errors.append(
                f"{class_name} is missing from the generated module."
            )
            continue

        members = [member.name for member in enum_class]
        if members != list(state_names):
            errors.append(
                f"{class_name} members {members} do not match "
                f"{list(state_names)}."
            )

    return errors
