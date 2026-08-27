from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timezone
import json

from .config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True)
    sender = Column(String(320), nullable=False)
    subject = Column(Text, nullable=False)
    verdict = Column(String(50), nullable=False)
    risk_score = Column(Float, nullable=False)
    confidence = Column(Float, nullable=False)
    reasons = Column(Text, nullable=False)
    signals = Column(Text, nullable=False)
    actions = Column(Text, nullable=False)
    qr_analysis = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

def init_db():
    Base.metadata.create_all(engine)
    # Automatically add missing column to existing SQLite database if needed
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE analyses ADD COLUMN qr_analysis TEXT"))
            conn.commit()
        except Exception:
            pass

def save_analysis(request, result):
    db = SessionLocal()
    try:
        row = Analysis(
            sender=request.sender,
            subject=request.subject,
            verdict=result["verdict"],
            risk_score=result["risk_score"],
            confidence=result["confidence"],
            reasons=json.dumps(result["reasons"]),
            signals=json.dumps(result["signals"]),
            actions=json.dumps(result["actions"]),
            qr_analysis=json.dumps(result.get("quishing") or {}),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row
    finally:
        db.close()

def get_recent(limit=50):
    db = SessionLocal()
    try:
        rows = db.query(Analysis).order_by(Analysis.id.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "sender": r.sender,
                "subject": r.subject,
                "verdict": r.verdict,
                "risk_score": r.risk_score,
                "confidence": r.confidence,
                "reasons": json.loads(r.reasons),
                "signals": json.loads(r.signals),
                "actions": json.loads(r.actions),
                "quishing": json.loads(r.qr_analysis) if getattr(r, "qr_analysis", None) else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
    finally:
        db.close()

def get_stats():
    rows = get_recent(10000)
    result = {
        "total": len(rows),
        "safe": 0,
        "suspicious": 0,
        "phishing": 0,
        "spear_phishing": 0,
    }
    for r in rows:
        key = r["verdict"].lower().replace("-", "_")
        if key in result:
            result[key] += 1
    return result
