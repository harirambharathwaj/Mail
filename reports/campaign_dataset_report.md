# Multi-Channel Phishing Campaign Dataset Report

## Summary & Corpus Overview
* **Total Unique Campaigns**: 12
* **Total Normalized Events**: 27
* **Supported Channels**: Email (40%), SMS (35%), WhatsApp (25%)
* **Languages**: English, Hindi (Devanagari), Tamil (Script), Hinglish, Tanglish
* **Total Pairwise Relationships**: 135

## Channel Distribution
* **Email Events**: 8
* **SMS Events**: 12
* **WhatsApp Events**: 7

## Zero-Leakage Split Guarantee
* **Train Pairs**: 105 (Campaigns: BENIGN_002_BANK_ALERT, CAMP_002_TNEB_POWER, CAMP_001_SBI_KYC, CAMP_004_HDFC_REWARDS, BENIGN_001_CORP_SYNC, CAMP_003_M365_MFA)
* **Validation Pairs**: 15 (Campaigns: CAMP_007_JOB_SCAM, CAMP_005_AIRTEL_SIM, CAMP_006_IT_REFUND)
* **Test Pairs**: 15 (Campaigns: CAMP_010_PM_KISAN, CAMP_008_NETFLIX, CAMP_009_PAYTM_QR)
* **Campaign Group Overlap**: 0 (**PASS**)
