import os
import joblib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="SQLGuardJS API (Stub)")

class DetectRequest(BaseModel):
    payload: str = Field(..., max_length=50000)

class DetectResponse(BaseModel):
    label: str
    is_malicious: bool
    confidence: float

# Global state for the model
ml_model = None
ml_vectorizer = None

@app.on_event("startup")
async def startup_event():
    global ml_model, ml_vectorizer
    base_path = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_path, 'models', 'stub_model.pkl')
    vec_path = os.path.join(base_path, 'models', 'stub_vectorizer.pkl')
    
    if os.path.exists(model_path) and os.path.exists(vec_path):
        ml_model = joblib.load(model_path)
        ml_vectorizer = joblib.load(vec_path)
    else:
        print("Warning: Stub model artifacts not found.")

@app.get("/health")
async def health():
    return {"status": "ok", "model_loaded": ml_model is not None}

@app.post("/api/v1/detect", response_model=DetectResponse)
async def detect(req: DetectRequest):
    if not ml_model or not ml_vectorizer:
        # Fallback if model not trained
        return DetectResponse(label="benign", is_malicious=False, confidence=0.0)
        
    try:
        X = ml_vectorizer.transform([req.payload])
        probs = ml_model.predict_proba(X)[0]
        classes = ml_model.classes_
        
        label = classes[probs.argmax()]
        
        is_malicious = label != "benign"
        
        return DetectResponse(
            label=label,
            is_malicious=is_malicious,
            confidence=float(probs.max())
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
