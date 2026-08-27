import re
import math
from typing import List, Dict, Set
from ..language_id import detect_language
from ..muril_model import get_muril

GENERIC_PHRASES = {
    "please verify your account", "verify your account", "account suspended",
    "urgent action required", "click here", "dear customer", "security alert",
    "verification code", "one time password", "otp"
}

def clean_text_for_sim(text: str) -> str:
    if not text:
        return ""
    t = text.lower()
    # Remove URLs and email addresses before text similarity check
    t = re.sub(r"https?://\S+", "", t)
    t = re.sub(r"www\.\S+", "", t)
    t = re.sub(r"\S+@\S+", "", t)
    t = re.sub(r"[^\w\s]", " ", t)
    return re.sub(r"\s+", " ", t).strip()

def get_char_ngrams(text: str, n: int = 3) -> Set[str]:
    cleaned = clean_text_for_sim(text)
    if len(cleaned) < n:
        return {cleaned} if cleaned else set()
    return {cleaned[i:i+n] for i in range(len(cleaned) - n + 1)}

def jaccard_similarity(set1: Set[str], set2: Set[str]) -> float:
    if not set1 or not set2:
        return 0.0
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    return float(intersection) / float(union)

def compute_text_similarity(text1: str, text2: str) -> float:
    """
    Computes hybrid character n-gram and token-level semantic similarity.
    Packs down generic phrase matches to prevent false correlations.
    """
    c1 = clean_text_for_sim(text1)
    c2 = clean_text_for_sim(text2)

    if not c1 or not c2:
        return 0.0

    if c1 == c2:
        # Check if the entire text is just a generic phrase
        if c1 in GENERIC_PHRASES:
            return 0.20  # Generic phrase alone is weak similarity
        return 0.95

    # 1. Character 3-gram similarity
    ngrams1 = get_char_ngrams(c1, 3)
    ngrams2 = get_char_ngrams(c2, 3)
    ngram_sim = jaccard_similarity(ngrams1, ngrams2)

    # 2. Token overlap similarity
    tokens1 = set(c1.split())
    tokens2 = set(c2.split())
    token_sim = jaccard_similarity(tokens1, tokens2)

    # 3. Check for regional / Indic language involvement via MuRIL
    lang_info1 = detect_language(text1)
    lang_info2 = detect_language(text2)

    muril_boost = 0.0
    if lang_info1.get("language") in ["hi", "ta", "hi+en", "ta+en"] or lang_info2.get("language") in ["hi", "ta", "hi+en", "ta+en"]:
        muril = get_muril()
        res1 = muril.predict(text1, lang_meta=lang_info1)
        res2 = muril.predict(text2, lang_meta=lang_info2)
        # Shared intent and high phishing probability across Indic text boost semantic correlation score
        if res1.get("detected_intent") == res2.get("detected_intent") and res1.get("detected_intent") not in ["General", None]:
            muril_boost = 0.15

    raw_score = 0.60 * ngram_sim + 0.40 * token_sim + muril_boost

    # De-weight generic phrase matches
    for generic in GENERIC_PHRASES:
        if generic in c1 and generic in c2 and len(c1) < 40 and len(c2) < 40:
            raw_score = min(0.35, raw_score)

    return min(1.0, round(raw_score, 4))
