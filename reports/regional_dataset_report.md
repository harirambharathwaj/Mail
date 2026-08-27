# Regional Dataset Quality & Distribution Report

## 1. Corpus Summary
* **Total Curated Samples**: 100
* **Training Partition (70%)**: 70
* **Validation Partition (15%)**: 15
* **Test Partition (15%)**: 15
* **Adversarial Test Suite**: 8
* **Zero-Leakage Guarantee**: `PASS (No template group overlaps)`

## 2. Language & Script Breakdown
| Language / Category | Script | Samples | Phishing (1) | Legitimate (0) |
| :--- | :--- | :---: | :---: | :---: |
| **Hindi Native** | Devanagari | 18 | 10 | 8 |
| **Tamil Native** | Tamil | 18 | 10 | 8 |
| **Hinglish (Code-Mixed)** | Latin | 18 | 10 | 8 |
| **Tanglish (Code-Mixed)** | Latin | 18 | 10 | 8 |
| **Romanized Hindi** | Latin | 14 | 8 | 6 |
| **Romanized Tamil** | Latin | 14 | 8 | 6 |
| **Total** | **All Scripts** | **100** | **56** | **44** |

## 3. Data Origin Distribution
* **Real Curated (Public Advisories, Cases, IndicNLP)**: 64
* **Synthetic Augmented (Controlled Scenarios)**: 20
* **Augmented Transliteration (Linguistic Variations)**: 16

## 4. Hard Negatives Included
* Corporate HR onboarding KYC requests in Hindi and Tamil
* Banking transaction credit alerts
* Office holiday and festival circulars
* Educational exam result announcements
* Travel and ticket booking confirmations
