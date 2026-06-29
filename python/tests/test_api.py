from fastapi.testclient import TestClient
from sqlguard_ml.api import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_detect():
    response = client.post("/api/v1/detect", json={"payload": "' OR '1'='1"})
    assert response.status_code == 200
    data = response.json()
    assert "label" in data
    assert "confidence" in data
    assert "probabilities" in data

def test_scan():
    response = client.post("/api/v1/scan", json=[{"payload": "test"}, {"payload": "<script>"}])
    assert response.status_code == 200
    data = response.json()
    assert "results" in data
    assert len(data["results"]) == 2

def test_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
