from __future__ import annotations
from typing import Tuple, Dict, Any, List

# The scoring below is transparent and tuned to be conservative.
# You can tweak weights as you gather more data.

WEIGHTS = {
    # Booleans
    "has_ip_in_host": 35,
    "has_at_symbol": 15,
    "double_slash_in_path": 8,
    "is_shortener": 18,
    "suspicious_tld": 12,
    "has_punycode": 12,
    "fragment_present": 4,

    # Numeric-ish
    "num_subdomains": 3.5,   # each subdomain adds risk
    "num_hyphens": 2.5,      # hyphens can be used for lookalikes
    "digits_ratio_host": 20, # 0-1 scaled; many digits in host looks auto-generated
    "digits_ratio_path": 5,  # digits in path are weaker
    "pct_encoded_ratio": 25, # % encoding may indicate obfuscation
    "keyword_hits": 7,       # per hit
    "num_params": 2,         # extra params can hide payloads
    "path_length": 0.05,     # per character
    "query_length": 0.06,    # per character
    "url_length": 0.03,      # per character (cap later)
    "host_length": 0.12,     # per character
    "tld_length": 1.5,       # very long tld is odd
    "scheme_https": -6,      # https reduces risk a bit (not too much)
}

CAPS = {
    "num_subdomains": 8,
    "num_hyphens": 15,
    "digits_ratio_host": 1.0,
    "digits_ratio_path": 1.0,
    "pct_encoded_ratio": 1.0,
    "keyword_hits": 5,
    "num_params": 15,
    "path_length": 400,
    "query_length": 500,
    "url_length": 2000,
    "host_length": 255,
    "tld_length": 24,
    "scheme_https": 1,
}

PRIMARY_SIGNALS = [
    "has_ip_in_host", "is_shortener", "suspicious_tld", "has_punycode",
    "has_at_symbol", "num_subdomains", "num_hyphens", "keyword_hits",
    "digits_ratio_host", "pct_encoded_ratio"
]

EXPLANATIONS = {
    "has_ip_in_host": "Host is a raw IP address instead of a domain.",
    "is_shortener": "The URL uses a known URL shortener.",
    "suspicious_tld": "The top-level domain is commonly abused.",
    "has_punycode": "Punycode detected in host (possible IDN homograph).",
    "has_at_symbol": "'@' present – browsers may ignore everything before it.",
    "double_slash_in_path": "Double slashes found in path (obfuscation pattern).",
    "fragment_present": "Fragment present; sometimes used to hide payloads.",
    "num_subdomains": "Unusually many subdomains.",
    "num_hyphens": "Many hyphens in host (lookalike pattern).",
    "digits_ratio_host": "Host contains a high ratio of digits.",
    "digits_ratio_path": "Path contains many digits.",
    "pct_encoded_ratio": "Percent-encoded characters in path/query.",
    "keyword_hits": "Contains classic phishing keywords.",
    "num_params": "Many query parameters.",
    "path_length": "Path is very long.",
    "query_length": "Query string is very long.",
    "url_length": "Overall URL is very long.",
    "host_length": "Host is very long.",
    "tld_length": "Unusually long top-level domain.",
    "scheme_https": "HTTPS in use (slightly reduces risk)."
}

def _cap(name: str, value: float) -> float:
    return min(float(value), CAPS.get(name, float(value)))

def _weighted(name: str, value: float) -> float:
    w = WEIGHTS.get(name, 0.0)
    v = _cap(name, value)
    return w * v

def score_from_features(feats: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
    raw_score = 0.0
    contributions: List[Dict[str, Any]] = []

    for name, weight in WEIGHTS.items():
        val = float(feats.get(name, 0))
        contrib = _weighted(name, val)
        if contrib != 0:
            contributions.append({
                "feature": name,
                "value": val,
                "weight": weight,
                "contribution": round(contrib, 2),
                "why": EXPLANATIONS.get(name, name.replace("_", " ").capitalize())
            })
        raw_score += contrib

    # Calibrate to 0–100 with soft cap
    # Negative can't go below 0, very high values cap near 100
    calibrated = max(0.0, min(100.0, raw_score))
    score = int(round(calibrated))

    # Sort contributions by absolute impact
    contributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)

    # Keep a concise "signals" subset for UI (top 8)
    top = contributions[:8]
    return score, top

def label_from_score(score: int) -> str:
    if score >= 60:
        return "Phishing"
    if score >= 40:
        return "Suspicious"
    return "Legitimate"
