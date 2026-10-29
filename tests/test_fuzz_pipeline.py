import json

import pytest

from src.testing.fuzz_pipeline import run_fuzz_pipeline

PYTHON_STAGE_NAMES = {
    "Python fuzzing (authentication)",
    "Python fuzzing (email)",
    "Python fuzzing (email_retry)",
}

ITERATIONS = 8
SEED = 12345


def _run(base, iterations: int = ITERATIONS, seed: int = SEED):
    return run_fuzz_pipeline(
        iterations=iterations,
        seed=seed,
        report_path=base / "latest_report.json",
        export_dir=base / "export",
    )


@pytest.fixture(scope="module")
def pipeline(tmp_path_factory):
    base = tmp_path_factory.mktemp("fuzz-main")
    return base, _run(base)


def test_pipeline_runs_every_fuzz_stage(pipeline):
    _, result = pipeline
    stage_names = {stage.name for stage in result.stages}

    assert {"Black-box CLI boundary fuzzing", "White-box deterministic fuzzing"} <= (
        stage_names
    )
    assert PYTHON_STAGE_NAMES <= stage_names
    assert result.summary["ERROR"] == 0


def test_pipeline_finds_no_python_invariant_violation(pipeline):
    _, result = pipeline
    python_stages = [
        stage for stage in result.stages if stage.name in PYTHON_STAGE_NAMES
    ]

    assert python_stages
    assert all(stage.status == "PASS" for stage in python_stages)


def test_pipeline_is_reproducible_for_a_fixed_seed(pipeline, tmp_path):
    _, first = pipeline
    second = _run(tmp_path)

    def snapshot(result):
        return [
            (stage.key, stage.status, stage.seed_data, stage.coverage)
            for stage in result.stages
        ]

    assert snapshot(first) == snapshot(second)


def test_pipeline_writes_json_markdown_and_html(pipeline):
    base, _ = pipeline

    assert (base / "latest_report.json").exists()
    saved = json.loads((base / "latest_report.json").read_text(encoding="utf-8"))
    assert saved["seed"] == SEED
    assert saved["iterations"] == ITERATIONS
    assert saved["stages"]

    export_dir = base / "export"
    html = (export_dir / "fuzzing_report.html").read_text(encoding="utf-8")
    markdown = (export_dir / "fuzzing_report.md").read_text(encoding="utf-8")
    assert (export_dir / "fuzzing_report.json").exists()

    # The HTML report must be self-contained: inline SVG, no external assets.
    assert "<!DOCTYPE html>" in html
    assert "<svg" in html and "http://www.w3.org/2000/svg" in html
    assert "http://" not in html.replace("http://www.w3.org/2000/svg", "")

    # The Markdown report embeds the flow as a Mermaid block.
    assert "```mermaid" in markdown
    assert "flowchart LR" in markdown


def test_pipeline_rejects_invalid_parameters(tmp_path):
    with pytest.raises(ValueError, match="iterations"):
        _run(tmp_path, iterations=0)

    with pytest.raises(ValueError, match="seed"):
        _run(tmp_path, seed=-1)
