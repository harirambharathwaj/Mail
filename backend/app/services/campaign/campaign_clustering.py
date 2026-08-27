from typing import List, Dict, Set, Any, Tuple
import uuid
from .campaign_schema import (
    NormalizedEvent, CampaignCluster, EvidenceBreakdown,
    EventThreatAssessment, PairwiseTelemetryItem
)
from .campaign_correlator import compute_pairwise_correlation, parse_timestamp
from ..language_id import detect_language
from ..muril_model import get_muril
from ..bert_model import get_bert
from ...config import settings

def cluster_events_into_campaigns(
    events: List[NormalizedEvent],
    temporal_window_hours: float = 24.0,
    correlation_threshold: float = 35.0
) -> Tuple[List[CampaignCluster], List[str], float, List[PairwiseTelemetryItem], List[EventThreatAssessment]]:
    """
    Performs graph connected component clustering on multi-channel events based on pairwise correlation scores.
    Events with correlation >= correlation_threshold are grouped into the same campaign.
    Also computes continuous individual ML threat assessments (BERT/MuRIL) and pairwise telemetry details.
    """
    if not events:
        return [], [], 0.0, [], []

    n = len(events)
    adj_matrix = [[0.0] * n for _ in range(n)]
    pairwise_details: Dict[Tuple[int, int], Tuple[float, EvidenceBreakdown, Dict[str, Any]]] = {}
    pairwise_telemetry_list: List[PairwiseTelemetryItem] = []
    max_pairwise_score = 0.0

    # 1. Compute individual ML threat assessments for every event using BERT / MuRIL
    bert = get_bert(settings.bert_model_path)
    muril = get_muril()
    event_assessments: List[EventThreatAssessment] = []

    for ev in events:
        eval_text = f"{ev.subject or ''}\n{ev.text}\n{' '.join(ev.urls)}\n{' '.join(ev.qr_payloads)}".strip()
        lang_meta = detect_language(eval_text)
        lang_code = lang_meta.get("language", "en")
        
        # Mask phone if SMS/WhatsApp
        sender_masked = ev.sender
        if ev.channel in ("sms", "whatsapp"):
            digits = "".join(c for c in ev.sender if c.isdigit())
            if len(digits) >= 10:
                if digits.startswith("91") and len(digits) == 12:
                    sender_masked = f"+91 {digits[2:6]}*****{digits[-2:]}"
                else:
                    sender_masked = f"+91 {digits[:4]}*****{digits[-2:]}"

        if lang_code in ["hi", "ta", "hi+en", "ta+en"]:
            muril_res = muril.predict(eval_text, lang_meta=lang_meta)
            p_prob = muril_res.get("phishing_probability", 0.0)
            intent = muril_res.get("detected_intent", "General Threat")
            lang_label = muril_res.get("language_detected", "Indic Code-Mixed")
        else:
            p_prob = bert.predict(eval_text) if bert else 0.5
            detected_intents = ev.intents or []
            intent = detected_intents[0] if detected_intents else "General Communication"
            lang_label = "English"

        # Smishing / WhatsApp phishing elevation: mobile messages delivering auth/compliance links
        if ev.channel in ("sms", "whatsapp") and ev.urls:
            p_prob = max(p_prob, 0.82)
            if intent == "General Communication":
                intent = "Compliance / Auth Lure"

        risk_pct = round(p_prob * 100.0, 1)
        if risk_pct >= 60.0:
            verdict = "PHISHING"
        elif risk_pct >= 30.0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        event_assessments.append(EventThreatAssessment(
            event_id=ev.event_id,
            channel=ev.channel,
            sender=ev.sender,
            sender_masked=sender_masked,
            phishing_risk_score=risk_pct,
            threat_verdict=verdict,
            detected_language=lang_label,
            detected_intent=intent
        ))

    # 2. Compute pairwise correlation graph matrix
    for i in range(n):
        for j in range(i + 1, n):
            score, evidence, telemetry = compute_pairwise_correlation(events[i], events[j], temporal_window_hours)
            adj_matrix[i][j] = score
            adj_matrix[j][i] = score
            pairwise_details[(i, j)] = (score, evidence, telemetry)
            pairwise_details[(j, i)] = (score, evidence, telemetry)
            max_pairwise_score = max(max_pairwise_score, score)

            # Summarize relationship
            if score >= 75.0:
                rel = "Strong Campaign Correlation"
            elif score >= 50.0:
                rel = "Likely Coordinated Campaign"
            elif score >= 25.0:
                rel = "Mild Tactical Overlap"
            else:
                rel = "Unrelated / Independent"

            ev_summary_parts = evidence.strong_evidence + evidence.medium_evidence
            ev_summary = ev_summary_parts[0] if ev_summary_parts else "No direct infrastructure or semantic overlap"

            pairwise_telemetry_list.append(PairwiseTelemetryItem(
                event_a_id=events[i].event_id,
                event_b_id=events[j].event_id,
                event_a_channel=events[i].channel,
                event_b_channel=events[j].channel,
                correlation_score=round(score, 1),
                relationship=rel,
                evidence_summary=ev_summary
            ))

    # 3. Graph Connected Components via BFS
    visited: Set[int] = set()
    clusters: List[List[int]] = []

    for i in range(n):
        if i not in visited:
            component: List[int] = []
            queue = [i]
            visited.add(i)
            while queue:
                curr = queue.pop(0)
                component.append(curr)
                for neighbor in range(n):
                    if neighbor not in visited and adj_matrix[curr][neighbor] >= correlation_threshold:
                        visited.add(neighbor)
                        queue.append(neighbor)
            clusters.append(component)

    campaign_clusters: List[CampaignCluster] = []
    unclustered_event_ids: List[str] = []

    for idx, comp in enumerate(clusters, 1):
        if len(comp) == 1:
            # Single isolated event with no correlation to other events
            unclustered_event_ids.append(events[comp[0]].event_id)
            continue

        comp_events = [events[i] for i in comp]
        comp_event_ids = [e.event_id for e in comp_events]
        comp_channels = list(dict.fromkeys([e.channel for e in comp_events]))

        # Aggregate max pairwise score & evidence across component members
        max_pair_score = 0.0
        strong_ev: List[str] = []
        medium_ev: List[str] = []
        weak_ev: List[str] = []

        shared_doms: Set[str] = set()
        shared_urls: Set[str] = set()
        shared_phones: Set[str] = set()
        shared_qrs: Set[str] = set()
        shared_hashes: Set[str] = set()
        shared_intents: Set[str] = set()
        languages: Set[str] = set()

        for i_idx in range(len(comp)):
            for j_idx in range(i_idx + 1, len(comp)):
                i_orig = comp[i_idx]
                j_orig = comp[j_idx]
                p_score, p_ev, p_telem = pairwise_details.get((i_orig, j_orig), (0.0, EvidenceBreakdown(strong_evidence=[], medium_evidence=[], weak_evidence=[]), {}))
                max_pair_score = max(max_pair_score, p_score)
                strong_ev.extend(p_ev.strong_evidence)
                medium_ev.extend(p_ev.medium_evidence)
                weak_ev.extend(p_ev.weak_evidence)

                shared_doms.update(p_telem.get("domains", []))
                shared_urls.update(p_telem.get("urls", []))
                shared_phones.update(p_telem.get("phones", []))
                shared_qrs.update(p_telem.get("qrs", []))
                shared_hashes.update(p_telem.get("hashes", []))

        # Collect event intents & languages
        for e in comp_events:
            shared_intents.update(e.intents)
            if "hi" in e.text.lower() or "aapka" in e.text.lower():
                languages.add("Hinglish")
            elif "ta" in e.text.lower() or "vanakkam" in e.text.lower():
                languages.add("Tamil")
            else:
                languages.add("English")

        # Compute temporal span
        timestamps = [parse_timestamp(e.timestamp) for e in comp_events]
        min_ts = min(timestamps)
        max_ts = max(timestamps)
        span_minutes = abs((max_ts - min_ts).total_seconds()) / 60.0

        # Calibrated Confidence Status
        if max_pair_score >= 80.0:
            confidence_label = "STRONG CORRELATION"
        elif max_pair_score >= 60.0:
            confidence_label = "LIKELY RELATED"
        elif max_pair_score >= 30.0:
            confidence_label = "POSSIBLE RELATIONSHIP"
        else:
            confidence_label = "WEAK / UNRELATED"

        clean_evidence = EvidenceBreakdown(
            strong_evidence=list(dict.fromkeys(strong_ev)),
            medium_evidence=list(dict.fromkeys(medium_ev)),
            weak_evidence=list(dict.fromkeys(weak_ev))
        )

        summary_text = (
            f"Campaign #{idx:03d} correlates {len(comp_events)} events across {', '.join(comp_channels)} channels "
            f"with a maximum correlation score of {max_pair_score}/100 within a {int(span_minutes)} minute temporal window."
        )

        campaign_clusters.append(CampaignCluster(
            campaign_id=f"C{idx:03d}",
            event_ids=comp_event_ids,
            channels=comp_channels,
            correlation_score=round(max_pair_score, 1),
            confidence_label=confidence_label,
            shared_infrastructure=list(shared_doms.union(shared_urls)),
            shared_domains=list(shared_doms),
            shared_urls=list(shared_urls),
            shared_phones=list(shared_phones),
            shared_qr_destinations=list(shared_qrs),
            shared_attachment_hashes=list(shared_hashes),
            shared_intents=list(shared_intents),
            temporal_window_span_minutes=round(span_minutes, 1),
            languages=list(languages),
            evidence=clean_evidence,
            summary=summary_text
        ))

    return campaign_clusters, unclustered_event_ids, max_pairwise_score, pairwise_telemetry_list, event_assessments
