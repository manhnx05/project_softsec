import argparse
import subprocess
import sys
from pathlib import Path

DEFAULT_FUZZ_ITERATIONS = 2000
DEFAULT_FUZZ_SEED = 0xC0FFEE


def run_streamlit() -> int:
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        "app.py",
        "--server.headless",
        "true",
    ]
    return subprocess.call(cmd)


def run_tests() -> int:
    cmd = [sys.executable, "-m", "pytest", "-q"]
    return subprocess.call(cmd)


def run_c_analysis() -> int:
    from src.c_analysis.runner import run_c_analysis

    report = run_c_analysis()
    print(report.to_dict())
    return 0


def run_fuzz(iterations: int, seed: int) -> int:
    from src.testing.fuzz_pipeline import run_fuzz_pipeline

    result = run_fuzz_pipeline(iterations=iterations, seed=seed)
    for stage in result.stages:
        print(f"[{stage.status:11}] {stage.name}: {stage.summary}")
    for finding in result.findings:
        print(f"  finding: {finding}")

    report_path = Path(result.report_path)
    print(
        f"Seed {result.seed}, {result.iterations} iterations per target, "
        f"{len(result.stages)} stages, "
        f"{'PASS' if result.passed else 'FAIL'}"
    )
    print(f"Artifacts: {report_path.parent}")
    return 0 if result.passed else 1


def run_scenarios() -> int:
    from src.testing.scenarios import run_e2e_scenarios

    rows = run_e2e_scenarios()
    for row in rows:
        print(f"[{row['Result']}] {row['ID']}: {row['Scenario']}")
    failed = [row for row in rows if row["Result"] != "PASS"]
    print(f"{len(rows) - len(failed)}/{len(rows)} LMS end-to-end scenarios passed")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Project SoftSec command-line entry point",
    )
    parser.add_argument(
        "--app",
        action="store_true",
        help="Run the Streamlit dashboard.",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run the project test suite.",
    )
    parser.add_argument(
        "--c-analysis",
        action="store_true",
        help="Run the C security analysis workflow.",
    )
    parser.add_argument(
        "--fuzz",
        action="store_true",
        help=(
            "Run the fuzzing pipeline (black-box, white-box, and Python) and "
            "export JSON/Markdown/HTML reports."
        ),
    )
    parser.add_argument(
        "--scenarios",
        action="store_true",
        help="Run the LMS end-to-end test scenarios.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_FUZZ_ITERATIONS,
        help="Fuzz iterations per target used by --fuzz.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_FUZZ_SEED,
        help="Reproducible fuzz seed used by --fuzz.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Show available commands.",
    )

    args = parser.parse_args(argv)

    if args.list or not any(
        [args.app, args.test, args.c_analysis, args.fuzz, args.scenarios]
    ):
        parser.print_help()
        return 0

    if args.app:
        return run_streamlit()

    if args.test:
        return run_tests()

    if args.c_analysis:
        return run_c_analysis()

    if args.fuzz:
        return run_fuzz(args.iterations, args.seed)

    if args.scenarios:
        return run_scenarios()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
