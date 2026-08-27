import math
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, List
from .campaign_schema import NormalizedEvent, EvidenceBreakdown
from .campaign_similarity import compute_text_similarity
from .campaign_entities import extract_registrable_domain, GENERIC_DOMAINS, PUBLIC_SHORTENERS
from ..language_id import detect_language
from ..muril_model import get_muril
from ..bert_model import get_bert
from ...config import settings

def parse_timestamp(ts_str: str) -> datetime:
    if not ts_str:
        return datetime.now(timezone.utc)
    for fmt in [
        "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M", "%d/%m/%Y %H:%M:%S", "%I:%M %p"
    ]:
        try:
            dt = datetime.strptime(ts_str.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass
    return datetime.now(timezone.utc)

def compute_pairwise_correlation(
    ev1: NormalizedEvent,
    ev2: NormalizedEvent,
    temporal_window_hours: float = 24.0
) -> Tuple[float, EvidenceBreakdown, Dict[str, Any]]:
    """
    Computes a continuous, dynamic ML-grounded correlation score (0 - 100) between two multi-channel events.
    Integrates:
    - Infrastructure & Destination Overlap (URLs, QR targets, eTLD+1 domains, attachments)
    - BERT & MuRIL Phishing Threat Probabilities & Intent Alignment
    - Character N-Gram & Lexical Semantic Similarity
    - Originating Sender Identities (Canonical E.164 phone numbers, sender domains)
    - Smooth Exponential Temporal Decay
    """
    strong_evidence: List[str] = []
    medium_evidence: List[str] = []
    weak_evidence: List[str] = []
    shared_telemetry: Dict[str, Any] = {
        "domains": [], "urls": [], "phones": [], "qrs": [], "hashes": []
    }

    # =========================================================================
    # 1. INFRASTRUCTURE & DESTINATION SIMILARITY (S_infra in [0, 1])
    # =========================================================================
    s_infra = 0.0

    # Combine URLs and QR code payloads
    dests1 = set(ev1.urls).union(set(ev1.qr_payloads))
    dests2 = set(ev2.urls).union(set(ev2.qr_payloads))
    common_dests = dests1.intersection(dests2)

    if common_dests:
        s_infra = 1.00
        url_sample = list(common_dests)[0]
        strong_evidence.append(f"Identical target URL / QR payload destination identified across channels: '{url_sample}'")
        shared_telemetry["urls"].extend(list(common_dests))
    else:
        # Check domain intersection across non-generic domains
        doms1 = {d for d in ev1.domains if d not in GENERIC_DOMAINS and d not in PUBLIC_SHORTENERS}
        doms2 = {d for d in ev2.domains if d not in GENERIC_DOMAINS and d not in PUBLIC_SHORTENERS}
        common_doms = doms1.intersection(doms2)

        if common_doms:
            s_infra = 0.85
            dom_sample = list(common_doms)[0]
            strong_evidence.append(f"Shared threat domain infrastructure: '{dom_sample}'")
            shared_telemetry["domains"].extend(list(common_doms))
        elif set(ev1.domains).intersection(set(ev2.domains)):
            # Shared benign public shortener / platform
            s_infra = 0.15
            weak_evidence.append("Shared generic platform domain (e.g. shortener/cloud host)")

    # Attachment Hash Match
    common_hashes = set(ev1.attachment_hashes).intersection(set(ev2.attachment_hashes)) if ev1.attachment_hashes and ev2.attachment_hashes else set()
    valid_hashes = {h for h in common_hashes if h and len(h) >= 8}
    if valid_hashes:
        s_infra = max(s_infra, 0.85)
        strong_evidence.append("Identical binary attachment payload hash detected across events")
        shared_telemetry["hashes"].extend(list(valid_hashes))

    # =========================================================================
    # 2. SENDER & IDENTITY SIMILARITY (S_sender in [0, 1])
    # =========================================================================
    s_sender = 0.0

    # Phone Number Match
    common_phones = set(ev1.phone_numbers).intersection(set(ev2.phone_numbers))
    if common_phones:
        s_sender = 0.90
        medium_evidence.append(f"Shared contact phone number identifier ({list(common_phones)[0]})")
        shared_telemetry["phones"].extend(list(common_phones))
    elif ev1.sender_domain and ev2.sender_domain and ev1.sender_domain == ev2.sender_domain and ev1.sender_domain not in GENERIC_DOMAINS:
        s_sender = 0.80
        medium_evidence.append(f"Matching sender domain identity: '{ev1.sender_domain}'")

    # =========================================================================
    # 3. SEMANTIC SIMILARITY & ML PHISHING THREAT (S_nlp in [0, 1], P_threat in [0, 1])
    # =========================================================================
    # Compute text similarity
    sim_score = compute_text_similarity(ev1.text, ev2.text)
    s_nlp = float(sim_score)

    if sim_score >= 0.70:
        medium_evidence.append(f"High semantic message alignment ({int(sim_score * 100)}% match)")
    elif sim_score >= 0.35:
        medium_evidence.append(f"Moderate campaign phrasing overlap ({int(sim_score * 100)}% match)")
    elif sim_score >= 0.15:
        weak_evidence.append(f"Minor lexical token overlap ({int(sim_score * 100)}% match)")

    # Model Phishing Inference via BERT & MuRIL
    lang1 = detect_language(ev1.text).get("language", "en")
    lang2 = detect_language(ev2.text).get("language", "en")

    bert = get_bert(settings.bert_model_path)
    muril = get_muril()

    # Get threat probabilities
    p1 = muril.predict(ev1.text).get("phishing_probability", 0.5) if lang1 in ["hi", "ta", "hi+en", "ta+en"] else (bert.predict(ev1.text) if bert else 0.5)
    p2 = muril.predict(ev2.text).get("phishing_probability", 0.5) if lang2 in ["hi", "ta", "hi+en", "ta+en"] else (bert.predict(ev2.text) if bert else 0.5)

    p_threat = math.sqrt(max(0.01, p1) * max(0.01, p2))

    # Shared Intent Lures
    common_intents = set(ev1.intents).intersection(set(ev2.intents))
    if common_intents:
        s_nlp = min(1.0, s_nlp + 0.15)
        medium_evidence.append(f"Matching threat intent lures: {', '.join(common_intents)}")

    # =========================================================================
    # 4. TEMPORAL PROXIMITY EXPONENTIAL DECAY (S_time in [0, 1])
    # =========================================================================
    dt1 = parse_timestamp(ev1.timestamp)
    dt2 = parse_timestamp(ev2.timestamp)
    diff_minutes = abs((dt1 - dt2).total_seconds()) / 60.0
    diff_hours = diff_minutes / 60.0

    # Smooth exponential decay: half-life ~ 3 hours (180 mins)
    s_time = math.exp(-diff_minutes / 180.0)

    if diff_minutes <= 15:
        medium_evidence.append(f"Rapid burst progression ({int(diff_minutes)} min gap)")
    elif diff_hours <= 6:
        weak_evidence.append(f"Events within active {round(diff_hours, 1)} hour window")

    # =========================================================================
    # 5. CONTINUOUS COMPOSITE WEIGHTED SCORING
    # =========================================================================
    # Dynamic weighting formula:
    # 45% Infrastructure + 20% NLP/Semantics + 15% Sender Identity + 10% Temporal + 10% Threat Model Prior
    raw_composite = (
        0.45 * s_infra +
        0.20 * s_nlp +
        0.15 * s_sender +
        0.10 * s_time +
        0.10 * p_threat
    )

    # Cross-channel coordination multiplier (e.g. Email + SMS with shared infrastructure)
    if ev1.channel != ev2.channel and (s_infra >= 0.70 or s_sender >= 0.70):
        raw_composite = min(1.0, raw_composite + 0.05)

    # Hard Negative Anti-Overcorrelation Gating
    if s_infra < 0.20 and s_sender < 0.20 and s_nlp < 0.35:
        raw_composite = min(0.30, raw_composite * 0.5)

    final_score = round(max(0.0, min(100.0, raw_composite * 100.0)), 1)

    evidence = EvidenceBreakdown(
        strong_evidence=strong_evidence,
        medium_evidence=medium_evidence,
        weak_evidence=weak_evidence
    )

    return final_score, evidence, shared_telemetry
