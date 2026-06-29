from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import os
from .detector import PayloadDetector

app = FastAPI(title="SQLGuard ML API")
detector = PayloadDetector()

class DetectRequest(BaseModel):
    payload: str

class DetectResponse(BaseModel):
    label: str
    confidence: float
    probabilities: list[float]

@app.on_event("startup")
async def startup_event():
    # Pre-load artifacts
    detector._load_artifacts()

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/api/v1/detect", response_model=DetectResponse)
async def detect(req: DetectRequest):
    try:
        res = detector.predict(req.payload)
        return DetectResponse(**res)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/scan")
async def scan(reqs: list[DetectRequest]):
    try:
        results = [detector.predict(r.payload) for r in reqs]
        return {"results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

dashboard_path = os.path.join(os.path.dirname(__file__), "static")

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    html_file = os.path.join(dashboard_path, "index.html")
    if os.path.exists(html_file):
        return FileResponse(html_file)
    return "<h1>SQLGuard ML Dashboard (Not Found)</h1>"
