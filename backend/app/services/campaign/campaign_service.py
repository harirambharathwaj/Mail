import uuid
from typing import List, Dict, Any
from .campaign_schema import (
    RawEventInput, NormalizedEvent, CampaignAnalyzeRequest, CampaignAnalyzeResponse
)
from .campaign_entities import (
    extract_entities_from_text, extract_registrable_domain, normalize_phone_number,
    extract_text_intents, normalize_url
)
from .campaign_clustering import cluster_events_into_campaigns

def normalize_raw_event(raw: RawEventInput) -> NormalizedEvent:
    event_id = raw.event_id or f"EVT_{uuid.uuid4().hex[:8].upper()}"
    channel = raw.channel.lower().strip()
    timestamp = raw.timestamp or "2026-08-28T10:00:00Z"
    sender = raw.sender or ""
    recipient = raw.recipient or ""
    subject = raw.subject or ""
    
    combined_text = f"{subject}\n{raw.body or raw.text or ''}".strip()
    
    # Extract entities
    urls_from_text, doms_from_text, phones_from_text = extract_entities_from_text(combined_text)
    
    # Merge explicit URLs passed in payload
    all_urls = list(urls_from_text)
    for u in (raw.urls or []):
        norm_u = normalize_url(u)
        if norm_u and norm_u not in all_urls:
            all_urls.append(norm_u)
            d = extract_registrable_domain(norm_u)
            if d and d not in doms_from_text:
                doms_from_text.append(d)

    # Extract sender domain & reply-to domain
    sender_dom = extract_registrable_domain(sender) if "@" in sender else ""
    reply_dom = extract_registrable_domain(raw.reply_to) if raw.reply_to and "@" in raw.reply_to else ""

    # Phone numbers
    phone_numbers = list(phones_from_text)
    if channel in ("sms", "whatsapp") and sender:
        norm_p = normalize_phone_number(sender)
        if norm_p and norm_p not in phone_numbers:
            phone_numbers.append(norm_p)

    intents = extract_text_intents(combined_text)

    return NormalizedEvent(
        event_id=event_id,
        channel=channel,
        timestamp=timestamp,
        sender=sender,
        recipient=recipient,
        subject=subject,
        text=combined_text,
        urls=all_urls,
        domains=doms_from_text,
        phone_numbers=phone_numbers,
        attachments=raw.attachment_names or [],
        attachment_hashes=raw.attachment_hashes or [],
        qr_payloads=raw.qr_payloads or [],
        sender_domain=sender_dom,
        reply_to_domain=reply_dom,
        intents=intents,
        data_origin=raw.data_origin or "real"
    )

def analyze_campaigns(request: CampaignAnalyzeRequest) -> CampaignAnalyzeResponse:
    if not request.events:
        return CampaignAnalyzeResponse(
            total_events_analyzed=0,
            likely_campaigns_count=0,
            overall_correlation_score=0.0,
            confidence_status="CLEAN / NO EVENTS",
            temporal_window_hours=request.temporal_window_hours or 24.0,
            campaigns=[],
            unclustered_events=[],
            warnings=["No events provided for campaign correlation analysis."]
        )

    # 1. Normalize all incoming raw events
    normalized_events = [normalize_raw_event(ev) for ev in request.events]

    # 2. Cluster normalized events into campaigns using graph connected components
    clusters, unclustered_ids, max_pairwise_score, pairwise_telemetry, event_assessments = cluster_events_into_campaigns(
        normalized_events,
        temporal_window_hours=request.temporal_window_hours or 24.0,
        correlation_threshold=35.0
    )

    if clusters:
        overall_score = max([c.correlation_score for c in clusters], default=max_pairwise_score)
    elif len(normalized_events) >= 2:
        overall_score = max_pairwise_score
    else:
        overall_score = 0.0

    if overall_score >= 80.0:
        conf_status = "STRONG CAMPAIGN CORRELATION DETECTED"
    elif overall_score >= 60.0:
        conf_status = "LIKELY MULTI-CHANNEL CAMPAIGN"
    elif overall_score >= 35.0:
        conf_status = "POSSIBLE CAMPAIGN RELATIONSHIP"
    elif overall_score >= 10.0:
        conf_status = "LOW / ISOLATED RELATIONSHIP"
    else:
        conf_status = "NO SIGNIFICANT CAMPAIGN CORRELATION"

    return CampaignAnalyzeResponse(
        total_events_analyzed=len(normalized_events),
        likely_campaigns_count=len(clusters),
        overall_correlation_score=round(overall_score, 1),
        confidence_status=conf_status,
        temporal_window_hours=request.temporal_window_hours or 24.0,
        campaigns=clusters,
        unclustered_events=unclustered_ids,
        event_assessments=event_assessments,
        pairwise_details=pairwise_telemetry,
        warnings=[]
    )
