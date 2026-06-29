from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from .detector import PayloadDetector

app = FastAPI(title="SQLGuard ML API")
detector = PayloadDetector()

class DetectRequest(BaseModel):
    payload: str = Field(..., max_length=50000)

class DetectResponse(BaseModel):
    label: str
    confidence: float
    probabilities: list[float]

@app.on_event("startup")
async def startup_event():
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
