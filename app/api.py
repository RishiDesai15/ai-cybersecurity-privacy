
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any

from app.parse_eml import parse_eml_bytes
from app.explain import build_explanation, highlight_tokens_simple
from app.features import quick_engineered_features
from model.infer import PhishModel

MODEL_PATH = os.getenv("MODEL_PATH", "model/artifacts")

# ---------------------------------------------------------------------------
# Lifespan: load the model once at startup, share via app.state
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(fastapi_app: FastAPI):
    fastapi_app.state.model = PhishModel(MODEL_PATH)
    yield
    fastapi_app.state.model = None


app = FastAPI(
    title="PhishAI — Cybersecurity & Privacy API",
    description="Privacy-first phishing email classifier with explainability.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_model() -> PhishModel:
    model = getattr(app.state, "model", None)
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded yet.")
    return model


def _build_response(subj: str, body: str, headers: Dict[str, Any]) -> dict:
    model = _get_model()
    pred  = model.predict(subj, body)
    feats = quick_engineered_features(subj, body, headers)
    reasons = build_explanation(feats, subj, body)
    tokens  = highlight_tokens_simple(body)
    return {
        "prediction": pred,
        "reasons": reasons,
        "tokens": tokens,
        "features": feats,
        "subject": subj,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

class EmailPayload(BaseModel):
    subject: str
    body: str
    headers: Optional[Dict[str, Any]] = None


@app.get("/health")
async def health():
    """Liveness check — also reports which model is loaded."""
    loaded_model = getattr(app.state, "model", None)
    return {
        "status": "ok",
        "model_path": getattr(loaded_model, "model_path", None),
    }


@app.post("/classify")
async def classify(payload: EmailPayload):
    """Classify a raw subject + body payload."""
    return _build_response(payload.subject, payload.body, payload.headers or {})


@app.post("/classify_eml")
async def classify_eml(file: UploadFile = File(...)):
    """Upload a .eml file and classify it."""
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted.")
    content = await file.read()
    subj, body, headers = parse_eml_bytes(content)
    return _build_response(subj, body, headers or {})
