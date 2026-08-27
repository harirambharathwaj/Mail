from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import uuid

class RawEventInput(BaseModel):
    event_id: Optional[str] = None
    channel: str = Field(..., description="Channel type: 'email', 'sms', or 'whatsapp'")
    timestamp: Optional[str] = None
    sender: Optional[str] = ""
    recipient: Optional[str] = ""
    subject: Optional[str] = ""
    body: Optional[str] = ""
    text: Optional[str] = ""
    urls: Optional[List[str]] = Field(default_factory=list)
    attachment_names: Optional[List[str]] = Field(default_factory=list)
    attachment_hashes: Optional[List[str]] = Field(default_factory=list)
    qr_payloads: Optional[List[str]] = Field(default_factory=list)
    headers: Optional[Dict[str, Any]] = Field(default_factory=dict)
    reply_to: Optional[str] = ""
    data_origin: Optional[str] = "real"  # "real", "synthetic", or "augmented"

class NormalizedEvent(BaseModel):
    event_id: str
    channel: str
    timestamp: str
    sender: str
    recipient: str
    subject: str
    text: str
    urls: List[str]
    domains: List[str]
    phone_numbers: List[str]
    attachments: List[str]
    attachment_hashes: List[str]
    qr_payloads: List[str]
    sender_domain: str
    reply_to_domain: str
    intents: List[str]
    data_origin: str

class CampaignAnalyzeRequest(BaseModel):
    events: List[RawEventInput]
    temporal_window_hours: Optional[float] = 24.0

class EvidenceBreakdown(BaseModel):
    strong_evidence: List[str]
    medium_evidence: List[str]
    weak_evidence: List[str]

class CampaignCluster(BaseModel):
    campaign_id: str
    event_ids: List[str]
    channels: List[str]
    correlation_score: float
    confidence_label: str
    shared_infrastructure: List[str]
    shared_domains: List[str]
    shared_urls: List[str]
    shared_phones: List[str]
    shared_qr_destinations: List[str]
    shared_attachment_hashes: List[str]
    shared_intents: List[str]
    temporal_window_span_minutes: float
    languages: List[str]
    evidence: EvidenceBreakdown
    summary: str

class EventThreatAssessment(BaseModel):
    event_id: str
    channel: str
    sender: str
    sender_masked: str
    phishing_risk_score: float
    threat_verdict: str
    detected_language: str
    detected_intent: str

class PairwiseTelemetryItem(BaseModel):
    event_a_id: str
    event_b_id: str
    event_a_channel: str
    event_b_channel: str
    correlation_score: float
    relationship: str
    evidence_summary: str

class CampaignAnalyzeResponse(BaseModel):
    total_events_analyzed: int
    likely_campaigns_count: int
    overall_correlation_score: float
    confidence_status: str
    temporal_window_hours: float
    campaigns: List[CampaignCluster]
    unclustered_events: List[str]
    event_assessments: Optional[List[EventThreatAssessment]] = Field(default_factory=list)
    pairwise_details: Optional[List[PairwiseTelemetryItem]] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
