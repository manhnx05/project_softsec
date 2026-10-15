import argparse
import subprocess
import sys


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
        "--list",
        action="store_true",
        help="Show available commands.",
    )

    args = parser.parse_args(argv)

    if args.list or not any([args.app, args.test, args.c_analysis]):
        parser.print_help()
        return 0

    if args.app:
        return run_streamlit()

    if args.test:
        return run_tests()

    if args.c_analysis:
        return run_c_analysis()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
