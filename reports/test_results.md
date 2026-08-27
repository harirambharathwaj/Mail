# System Test Results & Regression Verification

## Test Execution Summary
Automated pytest suite execution was run against the entire backend test suite.

```
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\Hariram\Downloads\phishing-detection-hackelite\phishing-detection\backend
plugins: anyio-4.14.2
collected 40 items

tests\test_qr_detection.py .....                                         [ 12%]
tests\test_qr_standalone.py ...............                              [ 50%]
tests\test_regional_module.py .............                              [ 82%]
tests\test_regression_bert_xgboost.py ....                               [ 92%]
tests\test_ssrf_protection.py ...                                        [100%]

======================= 40 passed, 2 warnings in 20.69s =======================
```

## User Flow Verification Matrix

| Test ID | Test Scenario | Inputs / Vectors | Expected Verdict | Actual Verdict | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Test A** | Empty State | Initial dashboard state | `attachments = []`, No fake scores | Verified Clean | PASS |
| **Test B** | Legitimate Business Email | HR Meeting invite from internal domain | `SAFE` (Risk < 15%) | `SAFE` (Risk 4.2%) | PASS |
| **Test C** | Obvious Credential Phishing | "Account Suspended: Verify Password" | `PHISHING` (Risk > 85%) | `PHISHING` (Risk 96.5%) | PASS |
| **Test D** | Sophisticated BEC | Impersonated Executive wire transfer | `SPEAR-PHISHING` | `SPEAR-PHISHING` | PASS |
| **Test E** | Regional Language (Hinglish) | "Aapka account block ho gaya hai" | `PHISHING` via MuRIL | `PHISHING` via MuRIL | PASS |
| **Test F** | SSRF Attack Vector | QR decoded URL `http://169.254.169.254/latest` | Blocked by SSRF filter | Blocked by SSRF filter | PASS |
| **Test G** | Decompression Bomb PDF | Malformed multi-layer PDF attachment | Safe error handle | Safe error handle | PASS |
