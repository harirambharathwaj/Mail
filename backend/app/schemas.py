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
    regional: Optional[dict] = None

class CampaignEventInput(BaseModel):
    event_id: Optional[str] = None
    channel: str = "email" # email, sms, whatsapp
    timestamp: Optional[str] = None
    sender: Optional[str] = ""
    recipient: Optional[str] = ""
    subject: Optional[str] = ""
    body: Optional[str] = ""
    text: Optional[str] = ""
    urls: Optional[List[str]] = Field(default_factory=list)
    qr_payloads: Optional[List[str]] = Field(default_factory=list)
    attachments: Optional[List[Any]] = Field(default_factory=list)

class CampaignAnalyzeRequest(BaseModel):
    events: List[CampaignEventInput] = Field(default_factory=list)
    correlation_threshold: Optional[float] = 60.0

class CampaignCluster(BaseModel):
    campaign_id: str
    correlation_score: float
    confidence: float
    event_count: int
    channels: List[str]
    languages: List[str]
    threat_theme: str
    shared_infrastructure: List[str]
    evidence: List[str]
    events: List[dict]

class CampaignAnalyzeResponse(BaseModel):
    total_events: int
    total_campaigns: int
    campaigns: List[CampaignCluster]
    unclustered_events: List[dict]
    pairwise_details: Optional[List[dict]] = Field(default_factory=list)
