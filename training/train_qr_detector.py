import os
import math
import re
import urllib.parse
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Recognized legitimate QR creation, document hosting, and corporate platforms
KNOWN_QR_DOMAINS = [
    "me-qr.com", "q.me-qr.com", "qr1.me-qr.com", "qrco.de", "flowcode.com",
    "qr-code-generator.com", "qr.io", "qr-code.io", "canva.com", "linktr.ee",
    "drive.google.com", "docs.google.com", "dropbox.com", "onedrive.live.com",
    "sharepoint.com", "adobe.com", "notion.so", "figma.com", "google.com",
    "wikipedia.org", "github.com", "microsoft.com", "apple.com"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".work", ".club", ".info", ".biz", ".live", ".online",
    ".site", ".zip", ".mov", ".tk", ".ml", ".ga", ".cf", ".gq", ".icu"
]

CRED_KEYWORDS = [
    "login", "verify", "auth", "account", "signin", "password", "update",
    "secure", "mfa", "2fa", "bank", "pay", "invoice", "payroll", "deposit"
]

KNOWN_BRANDS = [
    "microsoft", "office365", "google", "apple", "paypal", "amazon",
    "docusign", "netflix", "fedex", "dhl", "usps", "chase", "wellsfargo"
]

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)

def extract_url_features(url_str: str) -> list:
    url_low = str(url_str or "").strip().lower()
    parsed = urllib.parse.urlparse(url_low)
    domain = (parsed.netloc or "").lower()

    url_length = len(url_low)
    domain_length = len(domain)
    num_dots = domain.count(".")
    num_hyphens = domain.count("-")
    num_subdomains = max(0, num_dots - 1)
    is_ip = 1.0 if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain) else 0.0
    is_https = 1.0 if url_low.startswith("https://") else 0.0
    
    is_known_qr_host = 1.0 if any(domain == d or domain.endswith("." + d) for d in KNOWN_QR_DOMAINS) else 0.0
    has_suspicious_tld = 1.0 if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0.0
    has_cred_keywords = 1.0 if any(kw in url_low for kw in CRED_KEYWORDS) else 0.0
    
    has_brand_impersonation = 0.0
    if any(b in url_low for b in KNOWN_BRANDS) and not is_known_qr_host and not any(domain.endswith("." + b + ".com") or domain == b + ".com" for b in KNOWN_BRANDS):
        has_brand_impersonation = 1.0

    entropy = calculate_entropy(url_low)

    return [
        url_length,
        domain_length,
        num_dots,
        num_hyphens,
        num_subdomains,
        is_ip,
        is_https,
        is_known_qr_host,
        has_suspicious_tld,
        has_cred_keywords,
        has_brand_impersonation,
        entropy
    ]

FEATURE_NAMES = [
    "url_length", "domain_length", "num_dots", "num_hyphens", "num_subdomains",
    "is_ip", "is_https", "is_known_qr_host", "has_suspicious_tld",
    "has_cred_keywords", "has_brand_impersonation", "entropy"
]

def train_and_save_model(csv_path: str, output_model_path: str):
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)

    # Dataset augmentation for robust training
    extra_safe = [
        f"https://q.me-qr.com/menu_{i}" for i in range(50)
    ] + [
        f"https://qr1.me-qr.com/mobile/pdf/document_{i}.pdf" for i in range(50)
    ] + [
        f"https://qrco.de/campaign_{i}" for i in range(30)
    ] + [
        f"https://flowcode.com/p/code_{i}" for i in range(30)
    ] + [
        f"https://drive.google.com/file/d/doc_{i}/view" for i in range(40)
    ]

    extra_phish = [
        f"http://192.168.1.{i%250}/login-verify-account.xyz" for i in range(50)
    ] + [
        f"http://microsoft-support-login-{i}.com/auth/verify" for i in range(50)
    ] + [
        f"http://paypal-security-alert-{i}.top/verify" for i in range(50)
    ] + [
        f"http://appleid-confirm-device-{i}.info/login" for i in range(50)
    ]

    extra_df_safe = pd.DataFrame({"url": extra_safe, "label": 0})
    extra_df_phish = pd.DataFrame({"url": extra_phish, "label": 1})
    df_combined = pd.concat([df, extra_df_safe, extra_df_phish], ignore_index=True)

    X = np.array([extract_url_features(u) for u in df_combined["url"]])
    y = df_combined["label"].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Model Training Accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, y_pred))

    os.makedirs(os.path.dirname(output_model_path), exist_ok=True)
    joblib.dump(clf, output_model_path)
    print(f"Saved trained QR detector model to {output_model_path}")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    csv_file = os.path.join(base_dir, "dataset", "qr_phishing_dataset.csv")
    model_file = os.path.join(base_dir, "artifacts", "qr_detector_model.joblib")
    train_and_save_model(csv_file, model_file)
