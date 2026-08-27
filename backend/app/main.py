from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import init_db, save_analysis, get_recent, get_stats, get_recent_qr_scans
from .schemas import EmailRequest, AnalysisResponse
from .services.pipeline import analyze_email
from .services.qr_service import analyze_email_quishing, process_single_qr, analyze_qr_upload_file
from fastapi import UploadFile, File, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Any

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

class QRAnalyzeRequest(BaseModel):
    body: Optional[str] = ""
    attachments: Optional[List[Any]] = []
    inline_images: Optional[List[str]] = []
    raw_payload: Optional[str] = None

@app.post("/api/analyze/qr")
def analyze_qr(request: QRAnalyzeRequest):
    if request.raw_payload:
        item = process_single_qr({
            "source": "api_direct",
            "payload": request.raw_payload,
            "decoded": True,
            "filename": "direct_input"
        })
        from .services.qr_risk import calculate_overall_qr_risk
        return calculate_overall_qr_risk([item])
    
    return analyze_email_quishing(
        body=request.body or "",
        attachments=request.attachments or [],
        inline_images=request.inline_images or []
    )

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

@app.post("/api/qr/analyze")
async def analyze_uploaded_qr(file: UploadFile = File(...)):
    filename = file.filename or "uploaded_qr.png"
    ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Upload PNG, JPG, JPEG or WEBP."
        )

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail="File exceeds maximum allowed size (10 MB)."
        )

    return analyze_qr_upload_file(content, filename=filename)

@app.get("/api/qr/scans")
def get_qr_scans(limit: int = 50):
    return get_recent_qr_scans(limit)

@app.get("/api/alerts")
def alerts(limit: int = 50):
    return get_recent(limit)

@app.get("/api/stats")
def stats():
    return get_stats()

