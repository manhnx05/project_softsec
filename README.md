# LMS End-to-End Software Security

An educational LMS security simulator that models authentication and email
notification workflows using constraints, Kripke state models, and automated
tests.

## Run the project

Install the dependencies listed in `requirement.txt`, then run the test suite:

```powershell
python -m pip install -r requirement.txt
python -m pytest -q
```

Run the Streamlit interface with:

```powershell
streamlit run app.py
```

## C buffer analysis

The `csrc/` directory contains a deliberately vulnerable `memcpy` example, a
corrected implementation, a CBMC harness, and a deterministic mutation-fuzz
harness. The vulnerable version is isolated from the application and should
only be used by the analysis workflow.

Run the end-to-end analysis from the Streamlit **C Security Analysis** tab, or
from the project root:

```powershell
python -c "from src.c_analysis.runner import run_c_analysis; print(run_c_analysis().to_dict())"
```

GCC is required for static checks, sanitizer runs, and fuzzing. CBMC is
optional; when installed, the runner checks signed overflow, pointer safety,
and buffer bounds on both C implementations. If a tool is missing or cannot
run, the report marks that check unavailable or failed rather than claiming it
passed. The built-in formal model checks lengths from -32 through 32 and buffer
sizes 0, 1, 8, and 16; this bounded result is not a proof of every possible C
execution.

The mutation fuzzer uses a deterministic seed and exercises negative, boundary,
out-of-range, and pseudo-random lengths and byte contents. When compiler
sanitizer runtimes are available, it runs under AddressSanitizer and
UndefinedBehaviorSanitizer; otherwise it runs without instrumentation and
reports sanitizer coverage as unavailable. Its seed and iteration count are
included in the report so a run can be reproduced.

Some Windows MinGW GCC distributions do not include the ASan/UBSan runtimes.
Use a Clang toolchain or a Linux/WSL development distribution for sanitizer
coverage; the report labels missing sanitizer and CBMC tools as unavailable and
does not treat those checks as passing.

See [docs/flowcharts.md](docs/flowcharts.md) for the data-flow and state
transition diagrams.

## Authentication security

The authentication example stores passwords as PBKDF2-HMAC-SHA256 hashes with
independent random salts. It also uses randomly generated session tokens and
expires sessions after the configured lifetime.

This is a learning project with in-memory users and sessions. It is not a
production authentication service; a deployed system also needs persistent
storage, operational controls, monitoring, and security review.
