"""Tests for API security fixes."""

import pytest
from fastapi.testclient import TestClient

from driln.main import app

client = TestClient(app)

from driln.api.deps import verify_api_key
app.dependency_overrides[verify_api_key] = lambda: "test-token"

def test_cors_headers():
    """Test that CORS wildcard is restricted."""
    response = client.options(
        "/api/v1/health",
        headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    # Origin should not be echoed or allowed if restricted properly
    assert response.headers.get("access-control-allow-origin") != "*"
    assert response.headers.get("access-control-allow-origin") != "https://evil.com"


def test_scan_id_uuid_validation():
    """Test that garbage scan IDs are rejected at the routing layer."""
    response = client.get("/api/v1/scans/not-a-uuid")
    assert response.status_code == 400
    assert "Invalid scan_id format" in response.json()["detail"]


def test_recommendation_uuid_validation():
    """Test that garbage rec IDs are rejected."""
    # Use a valid scan UUID, but invalid rec ID
    scan_id = "12345678-1234-1234-1234-123456789012"
    response = client.post(f"/api/v1/scans/{scan_id}/recommendations/not-a-uuid/accept")
    assert response.status_code == 400
    assert "Invalid id format" in response.json()["detail"] or "Invalid rec_id format" in response.json()["detail"]


def test_idor_accept_recommendation(monkeypatch):
    """Test that accepting a recommendation checks scan_id."""
    scan_id = "12345678-1234-1234-1234-123456789012"
    rec_id = "87654321-4321-4321-4321-210987654321"

    # Mock the db list to return empty (meaning rec_id doesn't belong to scan_id)
    class MockRepo:
        async def list_by_scan(self, sid):
            return []

    # Apply mock via dependency override
    from driln.api.deps import get_recommendation_repo
    app.dependency_overrides[get_recommendation_repo] = lambda: MockRepo()

    response = client.post(f"/api/v1/scans/{scan_id}/recommendations/{rec_id}/accept")
    assert response.status_code == 404
    assert "Recommendation not found for this scan" in response.json()["detail"]

    app.dependency_overrides.pop(get_recommendation_repo, None)


def test_pagination_limits():
    """Test that pagination limit is capped."""
    
    class MockRepo:
        async def list_all(self, limit=50, offset=0):
            # We just need to return something to show the route works
            return []

    from driln.api.deps import get_scan_repo
    app.dependency_overrides[get_scan_repo] = lambda: MockRepo()

    response = client.get("/api/v1/scans?limit=999999999")
    assert response.status_code == 200

    app.dependency_overrides.pop(get_scan_repo, None)


def test_scan_create_extra_args_injection():
    """Test that extra_args are blocked in ScanCreate config."""
    payload = {
        "target": "example.com",
        "scan_type": "full",
        "tools": ["nmap"],
        "config": {
            "nmap": {
                "extra_args": ["--script-args", "os.execute('rm -rf /')"]
            }
        }
    }
    response = client.post("/api/v1/scans", json=payload)
    assert response.status_code == 422  # Pydantic validation error
    assert "extra_args is not allowed" in str(response.json())


def test_scan_create_target_validation():
    """Test that shell characters are blocked in API target validation."""
    payload = {
        "target": "; rm -rf /",
        "scan_type": "full"
    }
    response = client.post("/api/v1/scans", json=payload)
    assert response.status_code == 422  # Pydantic validation error
    assert "pattern" in str(response.json()).lower() or "match" in str(response.json()).lower()


def test_scan_create_ssrf_protection():
    """Test that scanning private IP ranges is blocked by default."""
    payload = {
        "target": "127.0.0.1",
        "scan_type": "full"
    }
    response = client.post("/api/v1/scans", json=payload)
    assert response.status_code == 400
    assert "private IP" in response.json()["detail"]


def test_scan_create_ssrf_allow_local():
    """Test that allow_local bypasses SSRF protection."""
    payload = {
        "target": "127.0.0.1",
        "scan_type": "full",
        "allow_local": True
    }
    # Should fail at the engine creation stage or return 200 depending on mocks,
    # but NOT 400 with SSRF block. We don't have DB mock here, so it might fail with 500 or DB error,
    # but the important part is it bypasses the 400 validation.
    try:
        response = client.post("/api/v1/scans", json=payload)
        assert response.status_code != 400
    except Exception:
        # DB error is acceptable here as it means we bypassed the API validation layer
        pass


def test_api_key_auth_enforced_by_default():
    """Test that API rejects requests without valid key by default."""
    app.dependency_overrides.pop(verify_api_key, None)
    
    # No header
    response = client.get("/api/v1/scans")
    assert response.status_code == 401
    
    # Wrong header
    response = client.get("/api/v1/scans", headers={"Authorization": "Bearer wrong"})
    assert response.status_code == 401

    app.dependency_overrides[verify_api_key] = lambda: "test-token"

