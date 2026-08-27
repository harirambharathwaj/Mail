import re
import math
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Set
from .campaign_normalizer import NormalizedEvent, COMMON_BENIGN_DOMAINS
from .muril_model import get_muril

# Generic urgency/boilerplate terms that must NOT trigger false campaign correlation
GENERIC_BOILERPLATE_TOKENS = {
    "urgent", "alert", "verify", "account", "login", "please", "click", "here",
    "service", "customer", "immediately", "notice", "update", "security", "warning",
    "dear", "your", "the", "and", "for", "with", "this", "from", "have", "been"
}

def tokenize_meaningful_text(text: str) -> Set[str]:
    words = re.findall(r'[a-zA-Z0-9\u0900-\u097F\u0B80-\u0BFF]{3,}', text.lower())
    meaningful = {w for w in words if w not in GENERIC_BOILERPLATE_TOKENS}
    return meaningful

def jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return round(intersection / union, 4) if union > 0 else 0.0

def compute_temporal_proximity(ts_a_iso: str, ts_b_iso: str) -> Tuple[float, float, str]:
    try:
        dt_a = datetime.fromisoformat(ts_a_iso.replace("Z", "+00:00"))
        dt_b = datetime.fromisoformat(ts_b_iso.replace("Z", "+00:00"))
        delta_seconds = abs((dt_a - dt_b).total_seconds())
        delta_hours = delta_seconds / 3600.0
        
        if delta_hours <= 1.0:
            score = 1.0
            desc = f"{int(delta_seconds // 60)} minute window (immediate sequence)"
        elif delta_hours <= 6.0:
            score = 0.85
            desc = f"{delta_hours:.1f} hour window (active multi-stage wave)"
        elif delta_hours <= 24.0:
            score = 0.70
            desc = f"{delta_hours:.1f} hour window (same-day campaign)"
        elif delta_hours <= 168.0: # 7 days
            score = 0.40
            desc = f"{delta_hours / 24:.1f} day window (weekly campaign cadence)"
        else:
            score = 0.10
            desc = f"{delta_hours / 24:.0f} day window (distant temporal separation)"
            
        return score, delta_hours, desc
    except Exception:
        return 0.5, 24.0, "Indeterminate temporal window"

class CampaignCorrelator:
    def __init__(self):
        self.muril = get_muril()

    def correlate_pair(self, ev_a: NormalizedEvent, ev_b: NormalizedEvent) -> Dict[str, Any]:
        evidence_strong = []
        evidence_medium = []
        evidence_weak = []

        # =====================================================================
        # 1. INFRASTRUCTURE CORRELATION (Strongest Signal)
        # =====================================================================
        infra_score = 0.0
        shared_urls = set(ev_a.urls).intersection(set(ev_b.urls))
        
        all_dest_a = set(ev_a.urls).union(set(ev_a.qr_payloads))
        all_dest_b = set(ev_b.urls).union(set(ev_b.qr_payloads))
        exact_dest_overlap = all_dest_a.intersection(all_dest_b)

        if exact_dest_overlap:
            infra_score = 1.00
            sample_u = list(exact_dest_overlap)[0]
            evidence_strong.append(f"Identical target URL / QR payload destination identified across channels: '{sample_u}'")
        else:
            # Check domain intersection across all URLs & QR targets
            doms_a = set(ev_a.registered_domains)
            for qr in ev_a.qr_payloads:
                d = extract_registered_domain(qr)
                if d: doms_a.add(d)
            
            doms_b = set(ev_b.registered_domains)
            for qr in ev_b.qr_payloads:
                d = extract_registered_domain(qr)
                if d: doms_b.add(d)

            valid_doms_a = {d for d in doms_a if d not in COMMON_BENIGN_DOMAINS}
            valid_doms_b = {d for d in doms_b if d not in COMMON_BENIGN_DOMAINS}
            common_doms = valid_doms_a.intersection(valid_doms_b)

            if common_doms:
                infra_score = 0.88
                evidence_strong.append(f"Shared threat domain infrastructure: {', '.join(common_doms)}")
            elif doms_a.intersection(doms_b):
                # Only shared common benign platform (e.g. google.com)
                infra_score = 0.20
                evidence_weak.append("Shared common generic platform domain (e.g., Google/Microsoft/Shortener)")

        # Attachment hash/name overlap
        att_a = {a if isinstance(a, str) else a.get("name", "") for a in ev_a.attachments}
        att_b = {b if isinstance(b, str) else b.get("name", "") for b in ev_b.attachments}
        att_overlap = [x for x in att_a.intersection(att_b) if x]
        if att_overlap:
            infra_score = max(infra_score, 0.80)
            evidence_strong.append(f"Shared payload attachment filename: {', '.join(att_overlap)}")

        # =====================================================================
        # 2. SENDER & IDENTITY CORRELATION
        # =====================================================================
        sender_score = 0.0
        if ev_a.sender_phone and ev_b.sender_phone and ev_a.sender_phone == ev_b.sender_phone:
            sender_score = 0.90
            evidence_medium.append(f"Same originating sender phone number ({ev_a.sender_phone_masked})")
        elif ev_a.sender_domain and ev_b.sender_domain and ev_a.sender_domain == ev_b.sender_domain and ev_a.sender_domain not in COMMON_BENIGN_DOMAINS:
            sender_score = 0.85
            evidence_medium.append(f"Matching sender envelope domain ({ev_a.sender_domain})")

        # =====================================================================
        # 3. CONTENT & MULTILINGUAL SEMANTIC CORRELATION
        # =====================================================================
        tokens_a = tokenize_meaningful_text(ev_a.full_text)
        tokens_b = tokenize_meaningful_text(ev_b.full_text)
        lexical_sim = jaccard_similarity(tokens_a, tokens_b)

        # Semantic Intent from MuRIL
        muril_a = self.muril.predict(ev_a.full_text, lang_meta=ev_a.lang_meta)
        muril_b = self.muril.predict(ev_b.full_text, lang_meta=ev_b.lang_meta)
        intent_a = muril_a.get("detected_intent", "General")
        intent_b = muril_b.get("detected_intent", "General")

        intent_match = (intent_a == intent_b and intent_a != "General Communication")

        content_score = 0.0
        if lexical_sim >= 0.40 and intent_match:
            content_score = 0.85
            evidence_medium.append(f"Strong semantic and phrasing alignment (Shared Intent: {intent_a})")
        elif intent_match:
            content_score = 0.65
            evidence_medium.append(f"Matching social-engineering threat theme ({intent_a})")
        elif lexical_sim >= 0.30:
            content_score = 0.50
            evidence_weak.append(f"Moderate lexical overlap across campaign phrasing (Jaccard: {lexical_sim:.2f})")
        else:
            content_score = lexical_sim * 0.5

        # =====================================================================
        # 4. TEMPORAL PROXIMITY
        # =====================================================================
        temporal_score, delta_hours, temporal_desc = compute_temporal_proximity(ev_a.timestamp, ev_b.timestamp)
        if temporal_score >= 0.70:
            evidence_medium.append(f"Close temporal proximity: {temporal_desc}")
        else:
            evidence_weak.append(f"Temporal separation: {temporal_desc}")

        # =====================================================================
        # 5. CROSS-CHANNEL ESCALATION BONUS
        # =====================================================================
        channel_bonus = 0.0
        if ev_a.channel != ev_b.channel:
            # Different channels (e.g. Email + SMS) that share infrastructure or high semantics indicate coordinated blitz
            if infra_score >= 0.80 or (content_score >= 0.60 and temporal_score >= 0.70):
                channel_bonus = 0.08
                evidence_medium.append(f"Cross-channel attack coordination ({ev_a.channel.upper()} ➔ {ev_b.channel.upper()})")

        # =====================================================================
        # COMPOSITE SCORING FORMULA
        # Anti-Overcorrelation Guarantee: content alone without infra or timing < 50
        # =====================================================================
        if infra_score >= 0.80:
            # Strong infrastructure anchor
            raw_score = 0.60 * infra_score + 0.20 * content_score + 0.15 * temporal_score + 0.05 * sender_score + channel_bonus
        elif sender_score >= 0.80:
            # Strong sender anchor
            raw_score = 0.45 * sender_score + 0.30 * content_score + 0.20 * temporal_score + 0.05 * infra_score + channel_bonus
        elif content_score >= 0.60 and temporal_score >= 0.70:
            # Semantic alignment within close timeframe
            raw_score = 0.45 * content_score + 0.35 * temporal_score + 0.15 * sender_score + 0.05 * infra_score + channel_bonus
        else:
            # Weak isolated similarity
            raw_score = (0.30 * content_score + 0.30 * temporal_score + 0.20 * infra_score + 0.20 * sender_score) * 0.70

        final_score = round(min(100.0, max(0.0, raw_score * 100)), 1)

        # Classify relationship level
        if final_score >= 80.0:
            relation_level = "STRONG_CORRELATION"
            relation_label = "Strong Campaign Correlation"
        elif final_score >= 60.0:
            relation_level = "LIKELY_RELATED"
            relation_label = "Likely Related Campaign"
        elif final_score >= 30.0:
            relation_level = "POSSIBLE_RELATION"
            relation_label = "Possible Relationship"
        else:
            relation_level = "UNRELATED"
            relation_label = "Unrelated / Weak Signal"

        return {
            "event_a_id": ev_a.event_id,
            "event_b_id": ev_b.event_id,
            "correlation_score": final_score,
            "relationship_level": relation_level,
            "relationship_label": relation_label,
            "signals": {
                "infrastructure_score": round(infra_score, 3),
                "content_score": round(content_score, 3),
                "sender_score": round(sender_score, 3),
                "temporal_score": round(temporal_score, 3),
                "delta_hours": round(delta_hours, 2)
            },
            "evidence": {
                "strong": evidence_strong,
                "medium": evidence_medium,
                "weak": evidence_weak
            }
        }

    def cluster_campaigns(self, events: List[NormalizedEvent], threshold: float = 60.0) -> Dict[str, Any]:
        n = len(events)
        if n == 0:
            return {"campaigns": [], "unclustered_events": [], "total_events": 0, "total_campaigns": 0}

        # Single event corner case
        if n == 1:
            return {
                "campaigns": [{
                    "campaign_id": "CAMP_001",
                    "correlation_score": 100.0,
                    "event_count": 1,
                    "channels": [events[0].channel],
                    "events": [events[0].to_dict()],
                    "threat_theme": events[0].lang_meta.get("summary", "Single-event inspection"),
                    "shared_infrastructure": events[0].registered_domains,
                    "evidence": ["Single isolated event analysis"]
                }],
                "unclustered_events": [],
                "total_events": 1,
                "total_campaigns": 1
            }

        # 1. Compute all pairwise correlation edges
        pairs = []
        adj = {i: [] for i in range(n)}

        for i in range(n):
            for j in range(i + 1, n):
                res = self.correlate_pair(events[i], events[j])
                pairs.append(res)
                if res["correlation_score"] >= threshold:
                    adj[i].append((j, res))
                    adj[j].append((i, res))

        # 2. Graph Connected Components Clustering
        visited = set()
        clusters = []
        unclustered = []

        for i in range(n):
            if i not in visited:
                component = []
                queue = [i]
                visited.add(i)

                while queue:
                    curr = queue.pop(0)
                    component.append(curr)
                    for neighbor, _ in adj[curr]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)

                if len(component) > 1:
                    clusters.append(component)
                else:
                    unclustered.append(events[component[0]].to_dict())

        # 3. Build Formatted Campaign Cluster Objects
        formatted_campaigns = []
        for c_idx, comp_indices in enumerate(clusters, 1):
            comp_events = [events[idx] for idx in comp_indices]
            
            # Find max/avg correlation within cluster
            comp_pairs = [p for p in pairs if any(p["event_a_id"] == events[a].event_id and p["event_b_id"] == events[b].event_id for a in comp_indices for b in comp_indices)]
            avg_score = round(sum(p["correlation_score"] for p in comp_pairs) / max(1, len(comp_pairs)), 1) if comp_pairs else 80.0
            
            # Collect shared infrastructure & evidence
            all_shared_domains = []
            for ev in comp_events:
                all_shared_domains.extend(ev.registered_domains)
            shared_domains_unique = list(dict.fromkeys(all_shared_domains))

            # Compile evidence
            strong_evs = []
            medium_evs = []
            for p in comp_pairs:
                strong_evs.extend(p["evidence"]["strong"])
                medium_evs.extend(p["evidence"]["medium"])
            
            combined_evidence = list(dict.fromkeys(strong_evs + medium_evs))
            if not combined_evidence:
                combined_evidence = ["Correlated via cross-channel temporal progression and thematic similarity"]

            # Predominant threat theme from MuRIL
            intents = [self.muril.predict(ev.full_text, lang_meta=ev.lang_meta).get("detected_intent") for ev in comp_events]
            valid_intents = [i for i in intents if i and i != "General Communication"]
            threat_theme = valid_intents[0] if valid_intents else "Multi-Channel Coordinated Phishing"

            formatted_campaigns.append({
                "campaign_id": f"CAMP_{c_idx:03d}",
                "correlation_score": avg_score,
                "confidence": round(min(0.99, 0.80 + (avg_score / 100.0) * 0.18), 2),
                "event_count": len(comp_events),
                "channels": list(dict.fromkeys([ev.channel for ev in comp_events])),
                "languages": list(dict.fromkeys([ev.lang_meta.get("language", "en") for ev in comp_events])),
                "threat_theme": threat_theme,
                "shared_infrastructure": shared_domains_unique,
                "evidence": combined_evidence[:6],
                "events": [ev.to_dict() for ev in comp_events]
            })

        return {
            "campaigns": formatted_campaigns,
            "unclustered_events": unclustered,
            "total_events": n,
            "total_campaigns": len(formatted_campaigns),
            "pairwise_details": pairs
        }

_correlator_instance = None

def get_campaign_correlator() -> CampaignCorrelator:
    global _correlator_instance
    if _correlator_instance is None:
        _correlator_instance = CampaignCorrelator()
    return _correlator_instance
