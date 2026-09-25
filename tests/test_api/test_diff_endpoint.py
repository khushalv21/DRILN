"""Routing-level smoke test for the scan diff endpoint.

The diff logic itself is covered at the service layer in
tests/test_intelligence/test_diff.py (including the "unknown scan"
case) — this only confirms the route exists and rejects malformed IDs
before touching the database, matching the pattern in
test_api_security.py.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from driln.api.deps import verify_api_key
from driln.main import app

client = TestClient(app)
app.dependency_overrides[verify_api_key] = lambda: "test-token"


def test_diff_endpoint_400_for_invalid_uuid():
    response = client.get("/api/v1/scans/not-a-uuid/diff")
    assert response.status_code == 400
    assert "Invalid scan_id format" in response.json()["detail"]
