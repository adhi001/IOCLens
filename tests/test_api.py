from fastapi.testclient import TestClient

from ioc_lens.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analysis_without_evidence_is_unknown():
    response = client.post("/api/v1/analyze", json={
        "indicator": "198.51.100.10",
        "indicator_type": "ipv4",
        "evidence": [],
    })
    assert response.status_code == 200
    body = response.json()
    assert body["risk_score"] is None
    assert body["verdict"] == "unknown"
    assert "not confirmed benign" in body["explanation"][0]


def test_analysis_with_evidence_returns_explanation():
    response = client.post("/api/v1/analyze", json={
        "indicator": "example.org",
        "indicator_type": "domain",
        "evidence": [{
            "source": "test-feed",
            "category": "malware",
            "severity": "high",
            "confidence": 0.9,
            "observed_at": "2026-11-24T10:00:00Z",
            "summary": "Observed in a controlled test dataset",
        }],
    })
    assert response.status_code == 200
    body = response.json()
    assert body["risk_score"] > 0
    assert body["evidence_count"] == 1
    assert "test-feed" in body["explanation"][0]


def test_invalid_hash_is_rejected():
    response = client.post("/api/v1/analyze", json={
        "indicator": "not-a-hash",
        "indicator_type": "sha256",
        "evidence": [],
    })
    assert response.status_code == 422


def test_lookup_returns_saved_analysis():
    payload = {
        "indicator": "203.0.113.8",
        "indicator_type": "ipv4",
        "evidence": [],
    }
    created = client.post("/api/v1/analyze", json=payload).json()
    fetched = client.get("/api/v1/lookup/ipv4/203.0.113.8")
    assert fetched.status_code == 200
    assert fetched.json()["analysis_id"] == created["analysis_id"]
