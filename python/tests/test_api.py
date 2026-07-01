from fastapi.testclient import TestClient
from sqlguard_ml.api import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_detect():
    # Make sure we have a trained model first
    from sqlguard_ml.train_stub import train_and_save
    train_and_save()
    
    # Needs to reload startup event or call it manually
    import asyncio
    from sqlguard_ml.api import startup_event
    asyncio.run(startup_event())
    
    # Test malicious
    response = client.post("/api/v1/detect", json={"payload": "admin' --"})
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["is_malicious"] is True
    assert res_json["label"] == "sqli"
    
    # Test benign
    response2 = client.post("/api/v1/detect", json={"payload": "hello world"})
    assert response2.status_code == 200
    res_json2 = response2.json()
    assert res_json2["is_malicious"] is False
    assert res_json2["label"] == "benign"
