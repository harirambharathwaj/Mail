from pydantic import BaseModel, Field
from typing import List, Optional, Any, Union

class EmailRequest(BaseModel):
    sender: Optional[str] = ""
    recipient: Optional[str] = ""
    subject: Optional[str] = ""
    body: Optional[str] = ""
    headers: Union[dict, list, str, Any] = Field(default_factory=dict)
    attachments: Union[List[Any], str, Any] = Field(default_factory=list)

class AnalysisResponse(BaseModel):
    id: Optional[int] = None
    verdict: str
    risk_score: float
    confidence: float
    reasons: List[str]
    signals: dict
    actions: List[str]
    urls: List[dict]
    quishing: Optional[dict] = None
