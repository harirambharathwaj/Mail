from pydantic import BaseModel, Field
from typing import List, Optional

class EmailRequest(BaseModel):
    sender: str
    recipient: Optional[str] = None
    subject: str = ""
    body: str = ""
    headers: dict = Field(default_factory=dict)
    attachments: List[dict] = Field(default_factory=list)

class AnalysisResponse(BaseModel):
    id: Optional[int] = None
    verdict: str
    risk_score: float
    confidence: float
    reasons: List[str]
    signals: dict
    actions: List[str]
    urls: List[dict]
