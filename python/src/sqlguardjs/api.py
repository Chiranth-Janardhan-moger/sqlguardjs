import os
import pickle
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from .artifacts import verify_artifact

MAX_REQUEST_BODY_BYTES = 65536

# Global state for the model
ml_model = None
ml_vectorizer = None


async def load_models():
    global ml_model, ml_vectorizer
    base_path = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_path, 'models', 'stub_model.pkl')
    vec_path = os.path.join(base_path, 'models', 'stub_vectorizer.pkl')

    try:
        with open(verify_artifact(model_path), "rb") as f:
            ml_model = pickle.load(f)
        with open(verify_artifact(vec_path), "rb") as f:
            ml_vectorizer = pickle.load(f)
    except Exception as exc:
        ml_model = None
        ml_vectorizer = None
        print(f"Warning: SQLGuardJS model unavailable: {exc}")


@asynccontextmanager
async def lifespan(_app):
    await load_models()
    yield


app = FastAPI(title="SQLGuardJS API (Stub)", lifespan=lifespan)


class RequestBodyTooLarge(Exception):
    pass


class BodySizeLimitMiddleware:
    def __init__(self, app, max_body_bytes: int):
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.max_body_bytes:
                    await JSONResponse(
                        status_code=413,
                        content={"detail": "request_too_large"}
                    )(scope, receive, send)
                    return
            except ValueError:
                await JSONResponse(
                    status_code=400,
                    content={"detail": "invalid_content_length"}
                )(scope, receive, send)
                return

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    raise RequestBodyTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await JSONResponse(
                status_code=413,
                content={"detail": "request_too_large"}
            )(scope, receive, send)


app.add_middleware(BodySizeLimitMiddleware, max_body_bytes=MAX_REQUEST_BODY_BYTES)

class DetectRequest(BaseModel):
    payload: str = Field(..., max_length=50000)

class DetectResponse(BaseModel):
    label: str
    is_malicious: bool
    confidence: float

@app.get("/health")
async def health():
    if ml_model is None or ml_vectorizer is None:
        return JSONResponse(
            status_code=503,
            content={"status": "unavailable", "model_loaded": False}
        )
    return {"status": "ok", "model_loaded": ml_model is not None}

@app.post("/api/v1/detect", response_model=DetectResponse)
async def detect(req: DetectRequest):
    if not ml_model or not ml_vectorizer:
        raise HTTPException(status_code=503, detail="model_unavailable")
        
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
    except Exception:
        raise HTTPException(status_code=500, detail="detection_failed")
