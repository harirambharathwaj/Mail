import re
from typing import Dict, Any, List

# Lexical dictionaries for Romanized Indic words and markers
HINDI_MARKERS = {
    "aapka", "aapke", "aapki", "kijiye", "karein", "kare", "karo", "karke", "karen",
    "suspend", "ho", "jayega", "gaya", "gayi", "turant", "abhi", "khata", "band",
    "paise", "jeeta", "hai", "hain", "nahi", "nahin", "baje", "kal", "subah", "raat",
    "shubhkaamnaye", "chhutti", "pranam", "namaste", "dhanyawad", "rupaye", "rupay",
    "bijli", "jama", "manzoor", "badhai", "khabar", "aadhar", "satta", "jankari",
    "bhejein", "bhejo", "dekh", "dekho", "khatre", "suraksha"
}

TAMIL_MARKERS = {
    "ungal", "ungalukku", "ungala", "pannunga", "panunga", "panni", "pannidalam",
    "aagum", "aagirukku", "aayiduchu", "aagala", "aagidum", "irukku", "irukanga",
    "kedaikum", "kedachurukku", "inaiku", "naalaiku", "kattunga", "kattala",
    "mudakkapadum", "saripaarkavum", "sollunga", "vanakkam", "nandri", "pudhu",
    "thappana", "rubai", "latcham", "vaanga", "vaangavum", "nadakkum", "paarkavum",
    "kudunga", "anupunga", "ellarum", "poga", "poguthu", "illana", "illai"
}

COMMON_ENGLISH_WORDS = {
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "i", "it", "for", "not",
    "on", "with", "he", "as", "you", "do", "at", "this", "but", "his", "by", "from",
    "they", "we", "say", "her", "she", "or", "an", "will", "my", "one", "all", "would",
    "there", "their", "what", "so", "up", "out", "if", "about", "who", "get", "which",
    "go", "me", "when", "make", "can", "like", "time", "no", "just", "him", "know",
    "take", "people", "into", "year", "your", "good", "some", "could", "them", "see",
    "other", "than", "then", "now", "look", "only", "come", "its", "over", "think",
    "also", "back", "after", "use", "two", "how", "our", "work", "first", "well",
    "way", "even", "new", "want", "because", "any", "these", "give", "day", "most", "us",
    "dear", "customer", "account", "verify", "link", "click", "urgent", "update", "bank",
    "service", "security", "login", "password", "bill", "payment", "card", "sim", "meeting",
    "report", "project", "team", "office", "please", "immediately", "within", "hours"
}

def detect_language(text: str) -> Dict[str, Any]:
    raw = str(text or "").strip()
    if not raw:
        return {
            "language": "unknown",
            "languages": [],
            "script": "unknown",
            "code_mixed": False,
            "transliterated": False,
            "confidence": 0.50,
            "detected_markers": [],
            "summary": "Empty text provided"
        }

    # 1. Script distribution analysis
    devanagari_chars = len(re.findall(r'[\u0900-\u097F]', raw))
    tamil_chars = len(re.findall(r'[\u0B80-\u0BFF]', raw))
    latin_chars = len(re.findall(r'[a-zA-Z]', raw))
    total_alpha = devanagari_chars + tamil_chars + latin_chars

    if total_alpha == 0:
        return {
            "language": "unknown",
            "languages": [],
            "script": "symbols",
            "code_mixed": False,
            "transliterated": False,
            "confidence": 0.50,
            "detected_markers": [],
            "summary": "No recognizable script characters found"
        }

    dev_ratio = devanagari_chars / total_alpha
    tam_ratio = tamil_chars / total_alpha
    lat_ratio = latin_chars / total_alpha

    # 1.5 Multi-native script co-occurrence (e.g. Devanagari subject + Tamil body)
    if devanagari_chars >= 3 and tamil_chars >= 3:
        is_mixed_latin = latin_chars >= 5
        langs = ["hi", "ta"] + (["en"] if is_mixed_latin else [])
        conf = round(min(0.99, max(0.85, (devanagari_chars + tamil_chars) / total_alpha)), 2)
        return {
            "language": "+".join(langs),
            "languages": langs,
            "script": "mixed",
            "code_mixed": True,
            "transliterated": False,
            "confidence": conf,
            "detected_markers": ["Devanagari Script", "Tamil Script"] + (["Latin Script"] if is_mixed_latin else []),
            "summary": f"Multilingual Code-Mixed (Devanagari + Tamil{' + English' if is_mixed_latin else ''})"
        }

    # 2. Native Devanagari script (Hindi)
    if dev_ratio >= 0.35:
        is_mixed = lat_ratio >= 0.15 or tamil_chars >= 3
        conf = round(min(0.99, max(0.80, dev_ratio)), 2)
        langs = ["hi"] + (["ta"] if tamil_chars >= 3 else []) + (["en"] if lat_ratio >= 0.15 else [])
        return {
            "language": "+".join(langs),
            "languages": langs,
            "script": "mixed" if is_mixed else "devanagari",
            "code_mixed": is_mixed,
            "transliterated": False,
            "confidence": conf,
            "detected_markers": ["Devanagari Script"] + (["Tamil Script"] if tamil_chars >= 3 else []),
            "summary": f"Native Hindi ({'Code-mixed with ' + ('Tamil' if tamil_chars >= 3 else 'English') if is_mixed else 'Devanagari script'})"
        }

    # 3. Native Tamil script
    if tam_ratio >= 0.35:
        is_mixed = lat_ratio >= 0.15 or devanagari_chars >= 3
        conf = round(min(0.99, max(0.80, tam_ratio)), 2)
        langs = ["ta"] + (["hi"] if devanagari_chars >= 3 else []) + (["en"] if lat_ratio >= 0.15 else [])
        return {
            "language": "+".join(langs),
            "languages": langs,
            "script": "mixed" if is_mixed else "tamil",
            "code_mixed": is_mixed,
            "transliterated": False,
            "confidence": conf,
            "detected_markers": ["Tamil Script"] + (["Devanagari Script"] if devanagari_chars >= 3 else []),
            "summary": f"Native Tamil ({'Code-mixed with ' + ('Hindi' if devanagari_chars >= 3 else 'English') if is_mixed else 'Tamil script'})"
        }

    # 4. Latin script analysis (English vs Hinglish vs Tanglish vs Transliterated Hindi/Tamil)
    words = [re.sub(r'[^a-zA-Z]', '', w.lower()) for w in raw.split() if w.strip()]
    words = [w for w in words if w]

    if not words:
        return {
            "language": "unknown",
            "languages": [],
            "script": "latin",
            "code_mixed": False,
            "transliterated": False,
            "confidence": 0.50,
            "detected_markers": [],
            "summary": "Latin characters without valid tokens"
        }

    hindi_hits = [w for w in words if w in HINDI_MARKERS]
    tamil_hits = [w for w in words if w in TAMIL_MARKERS]
    english_hits = [w for w in words if w in COMMON_ENGLISH_WORDS]

    hi_count = len(hindi_hits)
    ta_count = len(tamil_hits)
    en_count = len(english_hits)
    total_tokens = len(words)

    # A) Tanglish (Tamil + English code-mixed) or Romanized Tamil
    if ta_count >= 1 or (ta_count > 0 and ta_count >= hi_count):
        is_code_mixed = en_count >= 1
        is_pure_translit = en_count == 0 or (ta_count / max(1, total_tokens) >= 0.40)
        conf = round(min(0.98, max(0.75, 0.70 + (ta_count / total_tokens) * 0.5)), 2)
        
        return {
            "language": "ta+en" if is_code_mixed else "ta",
            "languages": ["ta", "en"] if is_code_mixed else ["ta"],
            "script": "latin",
            "code_mixed": is_code_mixed,
            "transliterated": True,
            "confidence": conf,
            "detected_markers": list(dict.fromkeys(tamil_hits[:6])),
            "summary": "Tamil-English (Tanglish) code-mixed" if is_code_mixed else "Romanized Tamil (Transliterated)"
        }

    # B) Hinglish (Hindi + English code-mixed) or Romanized Hindi
    if hi_count >= 1:
        is_code_mixed = en_count >= 1
        is_pure_translit = en_count == 0 or (hi_count / max(1, total_tokens) >= 0.40)
        conf = round(min(0.98, max(0.75, 0.70 + (hi_count / total_tokens) * 0.5)), 2)
        
        return {
            "language": "hi+en" if is_code_mixed else "hi",
            "languages": ["hi", "en"] if is_code_mixed else ["hi"],
            "script": "latin",
            "code_mixed": is_code_mixed,
            "transliterated": True,
            "confidence": conf,
            "detected_markers": list(dict.fromkeys(hindi_hits[:6])),
            "summary": "Hindi-English (Hinglish) code-mixed" if is_code_mixed else "Romanized Hindi (Transliterated)"
        }

    # C) Standard English
    if en_count > 0 or lat_ratio >= 0.80:
        return {
            "language": "en",
            "languages": ["en"],
            "script": "latin",
            "code_mixed": False,
            "transliterated": False,
            "confidence": 0.95 if en_count >= 3 else 0.85,
            "detected_markers": ["English vocabulary"],
            "summary": "Standard English"
        }

    # D) Uncertain / Mixed
    return {
        "language": "unknown",
        "languages": ["unknown"],
        "script": "mixed" if dev_ratio > 0 or tam_ratio > 0 else "latin",
        "code_mixed": True if (dev_ratio > 0 and lat_ratio > 0) or (tam_ratio > 0 and lat_ratio > 0) else False,
        "transliterated": False,
        "confidence": 0.55,
        "detected_markers": [],
        "summary": "Uncertain / Multilingual mixed text"
    }
