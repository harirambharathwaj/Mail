from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import init_db, save_analysis, get_recent, get_stats
from .schemas import EmailRequest, AnalysisResponse
from .services.pipeline import analyze_email

app = FastAPI(
    title="Phishing Detection API",
    version="1.0.0",
    description="Defensive phishing and social-engineering detection prototype."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()

from .services.bert_model import get_bert
from .services.fusion import fusion_model

@app.get("/api/health")
def health():
    bert = get_bert(settings.bert_model_path)
    bert_loaded = bert.loaded if bert else False
    xgboost_loaded = fusion_model.model is not None
    return {
        "status": "ok",
        "bert_loaded": bert_loaded,
        "xgboost_loaded": xgboost_loaded,
        "fallback_mode": not (bert_loaded and xgboost_loaded)
    }

@app.post("/api/analyze", response_model=AnalysisResponse)
def analyze(request: EmailRequest):
    result = analyze_email(request)
    row = save_analysis(request, result)
    result["id"] = row.id
    return result

@app.get("/api/alerts")
def alerts(limit: int = 50):
    return get_recent(limit)

@app.get("/api/stats")
def stats():
    return get_stats()
