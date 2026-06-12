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

## 🚀 Stress Testing

Driln's core engine was subjected to extreme pressure testing to ensure it can handle massive concurrency and database load. 

During our internal benchmarking, we built a script that mocks the external network tools to instantly return synthetic vulnerabilities, firing **500 concurrent scans** at the `ScanEngine` simultaneously.

### What the Benchmark Tested

- Flooding the `ScanEngine` with 500 concurrent requests using `asyncio.gather`.
- Pushing **5,000 simulated findings** into the SQLite database at exactly the same time.
- Validating the strength of `aiosqlite`'s transaction management (preventing "database is locked" errors).
- Passing the massive concurrent load through the `IntelligenceService` for deduplication and risk scoring.

**Benchmark Result:** Driln successfully processed this entire 500-scan payload flawlessly in less than **4 seconds** on standard hardware, with a 100% success rate.
