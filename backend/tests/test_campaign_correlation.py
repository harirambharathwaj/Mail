import pytest
from app.services.campaign_normalizer import NormalizedEvent, normalize_phone_number, extract_registered_domain
from app.services.campaign_correlator import get_campaign_correlator, jaccard_similarity, compute_temporal_proximity
from app.services.campaign.campaign_service import analyze_campaigns, RawEventInput, CampaignAnalyzeRequest

def test_normalization_across_channels():
    # Email event
    ev_email = NormalizedEvent({
        "event_id": "EVT_01",
        "channel": "email",
        "sender": "security@sbi-kyc.invalid",
        "subject": "Urgent KYC Update",
        "body": "Click link to verify: http://sbi-kyc.invalid/login",
        "urls": ["http://sbi-kyc.invalid/login"],
        "timestamp": "2026-03-10T10:00:00Z"
    })
    assert ev_email.channel == "email"
    assert ev_email.sender_domain == "sbi-kyc.invalid"
    assert "sbi-kyc.invalid" in ev_email.registered_domains

    # SMS event with phone
    ev_sms = NormalizedEvent({
        "event_id": "EVT_02",
        "channel": "sms",
        "sender": "+91 98765 43210",
        "body": "SBI Alert: verify now at http://short.example/sbi",
        "urls": ["http://short.example/sbi"],
        "timestamp": "2026-03-10T10:05:00Z"
    })
    assert ev_sms.channel == "sms"
    assert ev_sms.sender_phone == "+919876543210"
    assert "*****" in ev_sms.sender_phone_masked # Privacy masking check

    # WhatsApp event
    ev_wa = NormalizedEvent({
        "event_id": "EVT_03",
        "channel": "whatsapp",
        "sender": "+919876543210",
        "body": "Dear customer, update PAN card immediately.",
        "timestamp": "2026-03-10T10:15:00Z"
    })
    assert ev_wa.channel == "whatsapp"

def test_pairwise_infrastructure_correlation_exact_url():
    correlator = get_campaign_correlator()
    ev1 = NormalizedEvent({
        "event_id": "E1", "channel": "email", "body": "Verify account at http://evil-login.invalid/auth",
        "urls": ["http://evil-login.invalid/auth"], "timestamp": "2026-03-10T10:00:00Z"
    })
    ev2 = NormalizedEvent({
        "event_id": "E2", "channel": "sms", "body": "Immediate action: http://evil-login.invalid/auth",
        "urls": ["http://evil-login.invalid/auth"], "timestamp": "2026-03-10T10:08:00Z"
    })

    res = correlator.correlate_pair(ev1, ev2)
    assert res["correlation_score"] >= 80.0
    assert res["relationship_level"] == "STRONG_CORRELATION"
    assert any("Identical target URL" in ev for ev in res["evidence"]["strong"])

def test_pairwise_infrastructure_correlation_qr_payload():
    correlator = get_campaign_correlator()
    ev1 = NormalizedEvent({
        "event_id": "E1", "channel": "email", "body": "Scan attached QR code to re-authenticate",
        "qr_payloads": ["https://auth-portal.invalid/qr-target"], "timestamp": "2026-03-10T10:00:00Z"
    })
    ev2 = NormalizedEvent({
        "event_id": "E2", "channel": "whatsapp", "body": "Re-authentication required: https://auth-portal.invalid/qr-target",
        "urls": ["https://auth-portal.invalid/qr-target"], "timestamp": "2026-03-10T10:12:00Z"
    })

    res = correlator.correlate_pair(ev1, ev2)
    assert res["correlation_score"] >= 75.0

def test_anti_overcorrelation_generic_phrases_suppression():
    correlator = get_campaign_correlator()
    # Two totally unrelated events that only share generic phrases ("urgent verify account")
    ev1 = NormalizedEvent({
        "event_id": "E1", "channel": "email", "sender": "support@google.com",
        "body": "Security Alert: Please verify your account credentials.",
        "urls": ["https://myaccount.google.com/security"], "timestamp": "2026-03-10T10:00:00Z"
    })
    ev2 = NormalizedEvent({
        "event_id": "E2", "channel": "sms", "sender": "HDFCBK",
        "body": "Bank Alert: Please verify your account debit of Rs 500.",
        "urls": [], "timestamp": "2026-03-10T10:05:00Z"
    })

    res = correlator.correlate_pair(ev1, ev2)
    assert res["correlation_score"] < 35.0
    assert res["relationship_level"] == "UNRELATED"

def test_anti_overcorrelation_shared_benign_domains():
    correlator = get_campaign_correlator()
    # Two unrelated emails that both link to google.com
    ev1 = NormalizedEvent({
        "event_id": "E1", "channel": "email", "body": "Check doc: https://google.com/doc1",
        "urls": ["https://google.com/doc1"], "timestamp": "2026-03-10T10:00:00Z"
    })
    ev2 = NormalizedEvent({
        "event_id": "E2", "channel": "email", "body": "Check spreadsheet: https://google.com/sheet2",
        "urls": ["https://google.com/sheet2"], "timestamp": "2026-03-10T10:30:00Z"
    })

    res = correlator.correlate_pair(ev1, ev2)
    # Common public domain without other anchors should NOT correlate into a phishing campaign
    assert res["correlation_score"] < 35.0

def test_multilingual_semantic_correlation_muril():
    correlator = get_campaign_correlator()
    # Hindi Email + Hinglish SMS + Tamil WhatsApp targeting same bank KYC
    ev_hi = NormalizedEvent({
        "event_id": "E_HI", "channel": "email",
        "body": "प्रिय ग्राहक, आपका एसबीआई बैंक खाता आज रात निलंबित कर दिया जाएगा। पैन कार्ड सत्यापित करें: http://sbi-kyc.invalid",
        "urls": ["http://sbi-kyc.invalid"], "timestamp": "2026-03-10T10:00:00Z"
    })
    ev_hinglish = NormalizedEvent({
        "event_id": "E_HN", "channel": "sms",
        "body": "SBI ALERT: Aapka account block ho jayega. Verify KYC immediately: http://sbi-kyc.invalid",
        "urls": ["http://sbi-kyc.invalid"], "timestamp": "2026-03-10T10:08:00Z"
    })

    res = correlator.correlate_pair(ev_hi, ev_hinglish)
    assert res["correlation_score"] >= 80.0
    assert res["relationship_level"] == "STRONG_CORRELATION"

def test_graph_campaign_clustering_multi_channel():
    correlator = get_campaign_correlator()
    events = [
        # Campaign 1: SBI Blitz
        NormalizedEvent({"event_id": "C1_E1", "channel": "email", "body": "SBI KYC: http://sbi-fake.invalid", "urls": ["http://sbi-fake.invalid"], "timestamp": "2026-03-10T10:00:00Z"}),
        NormalizedEvent({"event_id": "C1_S2", "channel": "sms", "body": "SBI Alert: http://sbi-fake.invalid", "urls": ["http://sbi-fake.invalid"], "timestamp": "2026-03-10T10:05:00Z"}),
        # Campaign 2: TNEB Power Threat
        NormalizedEvent({"event_id": "C2_E3", "channel": "email", "body": "TNEB Power Cut: http://tneb-cut.invalid", "urls": ["http://tneb-cut.invalid"], "timestamp": "2026-03-10T14:00:00Z"}),
        NormalizedEvent({"event_id": "C2_S4", "channel": "sms", "body": "TNEB Alert: http://tneb-cut.invalid", "urls": ["http://tneb-cut.invalid"], "timestamp": "2026-03-10T14:15:00Z"}),
        # Isolated Benign Event
        NormalizedEvent({"event_id": "ISO_5", "channel": "email", "body": "HR Holiday Circular: office closed.", "urls": [], "timestamp": "2026-03-10T09:00:00Z"})
    ]

    result = correlator.cluster_campaigns(events, threshold=60.0)
    assert result["total_events"] == 5
    assert result["total_campaigns"] == 2 # 2 distinct multi-channel campaigns formed
    assert len(result["unclustered_events"]) == 1 # 1 isolated message
    assert result["unclustered_events"][0]["event_id"] == "ISO_5"

def test_campaign_service_api_end_to_end():
    req = CampaignAnalyzeRequest(
        events=[
            RawEventInput(
                event_id="EV1", channel="email", sender="security@sbi-fraud.invalid",
                subject="Urgent KYC", body="Verify at http://sbi-fraud.invalid/login",
                urls=["http://sbi-fraud.invalid/login"], timestamp="2026-03-10T10:00:00Z"
            ),
            RawEventInput(
                event_id="EV2", channel="sms", sender="+919876543210",
                body="SBI Alert: http://sbi-fraud.invalid/login",
                urls=["http://sbi-fraud.invalid/login"], timestamp="2026-03-10T10:07:00Z"
            )
        ],
        temporal_window_hours=24.0
    )

    resp = analyze_campaigns(req)
    assert resp.total_events_analyzed == 2
    assert resp.likely_campaigns_count == 1
    assert resp.overall_correlation_score >= 60.0
    assert "sbi-fraud.invalid" in str(resp.campaigns[0].shared_infrastructure) or "sbi-fraud.invalid" in str(resp.campaigns[0].evidence)

def test_phone_number_privacy_masking():
    info1 = normalize_phone_number("+91 98765 43210")
    assert info1["canonical"] == "+919876543210"
    assert "*****" in info1["masked"]
    assert not info1["masked"].endswith("43210") # Middle digits redacted

    info2 = normalize_phone_number("9876543210")
    assert info2["canonical"].startswith("+91")
