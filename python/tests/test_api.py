from sqlguardjs import api
from sqlguardjs.api import app
from sqlguardjs.detector import PayloadDetector
from pathlib import Path
import asyncio
import httpx
import pytest

def load_models():
    asyncio.run(api.load_models())

async def request(method, url, **kwargs):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await getattr(client, method)(url, **kwargs)

def get(url, **kwargs):
    return asyncio.run(request("get", url, **kwargs))

def post(url, **kwargs):
    return asyncio.run(request("post", url, **kwargs))

def test_health():
    load_models()
    response = get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_detect():
    models_dir = Path(__file__).resolve().parents[1] / "src" / "sqlguardjs" / "models"
    assert (models_dir / "stub_model.pkl").exists()
    assert (models_dir / "stub_vectorizer.pkl").exists()
    load_models()
    
    # Test malicious
    response = post("/api/v1/detect", json={"payload": "admin' --"})
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["is_malicious"] is True
    assert res_json["label"] == "sqli"
    
    # Test benign
    response2 = post("/api/v1/detect", json={"payload": "hello world"})
    assert response2.status_code == 200
    res_json2 = response2.json()
    assert res_json2["is_malicious"] is False
    assert res_json2["label"] == "benign"

def test_detect_fails_closed_when_model_unavailable(monkeypatch):
    monkeypatch.setattr(api, "ml_model", None)
    monkeypatch.setattr(api, "ml_vectorizer", None)

    response = post("/api/v1/detect", json={"payload": "admin' --"})

    assert response.status_code == 503
    assert response.json()["detail"] == "model_unavailable"

def test_health_fails_when_model_unavailable(monkeypatch):
    monkeypatch.setattr(api, "ml_model", None)
    monkeypatch.setattr(api, "ml_vectorizer", None)

    response = get("/health")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable", "model_loaded": False}

def test_detect_rejects_oversized_request_before_detection():
    response = post("/api/v1/detect", content=b"{" + b"a" * 70000 + b"}")

    assert response.status_code == 413
    assert response.json()["detail"] == "request_too_large"

def test_payload_detector_rejects_invalid_input_before_loading(monkeypatch):
    detector = PayloadDetector()
    monkeypatch.setattr(detector, "_load_artifacts", lambda: (_ for _ in ()).throw(AssertionError("loaded")))

    with pytest.raises(ValueError, match="payload too large"):
        detector.predict("x" * 50001)

    with pytest.raises(TypeError, match="text must be a string"):
        detector.predict(123)
