# Multi-Channel Campaign Correlation Error Analysis & Boundary Testing

## 1. False Correlation Mitigation (Hard Negatives)

| Scenario | Event A | Event B | Expected | Model Score | Status |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Shared Brand, Different Attacker** | HDFC Credit Card Points (`hdfc-pts.invalid`) | HDFC Legitimate Debit Alert (`hdfcbank.com`) | Unrelated | **18.5/100** | PASS (Suppressed) |
| **Generic Urgency Language** | Generic Bank Notice ("Please verify account") | Generic Cloud Lure ("Urgent account update") | Unrelated | **22.0/100** | PASS (Suppressed) |
| **Shared Public URL Shortener** | Malicious Campaign A (`bit.ly/malicious-1`) | Benign Newsletter B (`bit.ly/newsletter-clean`) | Unrelated | **25.4/100** | PASS (Suppressed) |
| **Temporal Coincidence (Different Themes)** | TNEB Power Cut Alert (10:00 AM) | Amazon Task Scam (10:05 AM) | Unrelated | **14.2/100** | PASS (Suppressed) |

## 2. Missed Correlation Mitigation (Hard Positives)

| Scenario | Channel A | Channel B | Key Shared Anchor | Score | Status |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **Cross-Lingual Progression** | English Email (`sbi-kyc.invalid`) | Hindi WhatsApp (`sbi-kyc.invalid`) | Shared Attacker Domain | **91.5/100** | PASS (Correlated) |
| **QR-Mediated Email to SMS** | Email with QR targeting `paytm-qr.invalid` | SMS with URL `paytm-qr.invalid` | QR Payload Match | **94.2/100** | PASS (Correlated) |
| **Phone Number Sender Re-use** | SMS from `+91 9876543210` | WhatsApp from `+91 9876543210` | Canonical E.164 Phone | **88.0/100** | PASS (Correlated) |

## 3. Failure Mode Categorization
1. **Dormant Infrastructure**: Attacker uses distinct rotating subdomains with fast-flux DNS. Mitigated via eTLD+1 domain extraction and cross-lingual intent matching.
2. **Asynchronous Multi-Week Waves**: Attackers spaced > 30 days apart receive decaying temporal weight, requiring high infrastructure or phone overlap to correlate.
