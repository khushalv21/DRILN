# Testing Guide

Driln includes a comprehensive automated test suite to ensure the core engine, security features, and intelligence layer are functioning correctly before deployment.

## Running the Tests

To run the full test suite, navigate to the `driln` project directory and use `pytest`. You must include `PYTHONPATH=.` so the tests can import the local Driln modules correctly:

```bash
PYTHONPATH=. pytest tests/
```

If you want more detailed output (to see exactly which tests are running), you can add the verbose flag:

```bash
PYTHONPATH=. pytest tests/ -v
```

## What the Tests Cover

The test suite is divided into several areas, primarily focusing on security and data accuracy:

1. **API Security (`test_api_security.py`)**
   - Verifies that API keys are strictly required to access endpoints.
   - Ensures that input validation actively blocks shell injection attempts (e.g., preventing a user from entering `; rm -rf /` as a scan target).
   - Confirms that Server-Side Request Forgery (SSRF) protections are in place (e.g., preventing scans against internal `127.0.0.1` addresses).

2. **Intelligence Layer (`test_intelligence/`)**
   - **Risk Scoring:** Ensures vulnerabilities are assigned accurate 0-100 risk scores based on severity and exposure.
   - **Deduplication:** Verifies that duplicate findings from different tools are successfully merged into one.
   - **Correlation:** Tests that related findings (like a vulnerable service and an exploit) are properly grouped together.

If all tests pass, the system will output a green success message, indicating Driln is stable and ready to use.

## Concurrency Benchmark

[`scripts/benchmark_concurrency.py`](scripts/benchmark_concurrency.py) stress-tests the async
engine and SQLite session factory under concurrent load. It registers a fake tool that returns
synthetic findings instantly (no real network tools involved — this measures the engine, not
subfinder/nuclei), then fires many scans at `ScanEngine` simultaneously via `asyncio.gather` into
an isolated temp SQLite database.

Run it yourself:

```bash
PYTHONPATH=. python scripts/benchmark_concurrency.py --scans 500 --findings-per-scan 10
```

Sample output from this repo's dev machine (Apple Silicon, Python 3.12, three consecutive runs):

```
Scans requested:      500
Scans completed:      500/500
Exceptions raised:    0
Findings persisted:   5000 (expected 5000)
Wall clock time:      2.2s – 2.4s
Success rate:         100.0%
```

Results are hardware- and Python-version-dependent — re-run the script rather than trusting these
numbers on a different machine.
