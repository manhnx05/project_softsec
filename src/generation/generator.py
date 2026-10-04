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
        ).parent / "templates"

        self.environment = Environment(
            loader=FileSystemLoader(template_dir)
        )

    def generate_state_enum(
        self,
        function: FunctionSpec,
        output_dir: str = "generated",
    ):

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