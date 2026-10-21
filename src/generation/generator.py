import shutil
from pathlib import Path

from jinja2 import (
    Environment,
    FileSystemLoader,
)

from src.specification.schemas import FunctionSpec


class CodeGenerator:

    def __init__(self):

        template_dir = Path(
            __file__
        ).parent / "templetes"

        self.environment = Environment(
            loader=FileSystemLoader(template_dir)
        )

    def generate_state_enum(
        self,
        function: FunctionSpec,
        output_dir: str = "generated",
    ) -> Path:

        output_path = Path(output_dir)
        output_path.mkdir(
            parents=True,
            exist_ok=True,
        )

        template = self.environment.get_template(
            "state.py.j2"
        )

        content = template.render(
            class_name=f"{function.name}State",
            states=function.states,
        )

        file_path = (
            output_path
            / f"{function.name.lower()}_states.py"
        )

        file_path.write_text(
            content,
            encoding="utf-8",
        )

        return file_path

    def generate_safe_c_files(
        self,
        output_dir: str = "generated",
    ) -> list[Path]:
        """Copy the canonical safe C implementation and its public header."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        project_root = Path(__file__).resolve().parents[2]
        source_files = (
            project_root / "csrc" / "safe" / "buffer_copy.c",
            project_root / "csrc" / "include" / "buffer_copy.h",
        )
        generated_files = []
        for source in source_files:
            destination = output_path / source.name
            shutil.copyfile(source, destination)
            generated_files.append(destination)

        return generated_files