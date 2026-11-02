from __future__ import annotations
import re
import urllib.parse as urlparse
from typing import Dict, Any
import tldextract

SUSPICIOUS_TLDS = {
    # Commonly abused, free or cheap / historically problematic TLDs
    "zip", "mov", "top", "xyz", "club", "info", "cn", "ru", "tk", "ml", "ga", "cf", "gq",
    "work", "wang", "rest", "country", "stream", "download", "loan", "men", "party",
    "click", "cam", "kim", "mom", "date", "link"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "tiny.cc", "soo.gd", "s.id", "lnkd.in", "rb.gy"
}

PHISH_KEYWORDS = {
    "login", "signin", "verify", "update", "secure", "bank", "wallet",
    "password", "account", "confirm", "billing", "invoice", "unlock",
    "support", "helpdesk", "pay", "payment", "mfa", "2fa", "otp"
}

IPV4_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)

def normalize_url(url: str) -> str:
    """Ensure scheme exists and strip surrounding whitespace."""
    url = (url or "").strip()
    if not url:
        return url
    # If no scheme, assume http
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    # Remove default ports and normalize
    parsed = urlparse.urlsplit(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc
    path = parsed.path or "/"
    query = parsed.query
    fragment = ""  # ignore fragment in normalized output

    # Drop default ports
    hostname = netloc
    if ":" in netloc:
        host, port = netloc.rsplit(":", 1)
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            hostname = host

    normalized = urlparse.urlunsplit((scheme, hostname, path, query, fragment))
    return normalized

def url_from_request(data: dict) -> str:
    for key in ("url", "u", "link"):
        if key in data:
            return str(data[key])
    return ""

def _is_ipv4(host: str) -> bool:
    if not host:
        return False
    if IPV4_RE.match(host):
        # basic range check (0-255) to avoid 999.999.999.999
        parts = host.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    return False

def _digits_ratio(s: str) -> float:
    if not s:
        return 0.0
    digits = sum(c.isdigit() for c in s)
    return digits / max(1, len(s))

def _pct_encoded_ratio(s: str) -> float:
    if not s:
        return 0.0
    pct = s.count("%")
    return pct / max(1, len(s))

def _has_punycode(host: str) -> bool:
    return host.startswith("xn--") or ".xn--" in host

def extract_features(url: str) -> Dict[str, Any]:
    """
    Extract URL-based features for phishing detection.
    Returns a dict of primitive features that scoring can consume.
    """
    parsed = urlparse.urlsplit(url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    netloc = parsed.netloc or ""

    # Derived attributes
    ext = tldextract.extract(host)
    domain = ".".join(part for part in [ext.domain] if part)
    sld_tld = ".".join([p for p in [ext.domain, ext.suffix] if p])
    registered_domain = ext.registered_domain or ""
    tld = ext.suffix.split(".")[-1] if ext.suffix else ""

    # Primitive numeric/boolean/string features
    feats: Dict[str, Any] = {}
    feats["scheme_https"] = int(scheme == "https")
    feats["url_length"] = len(url)
    feats["host_length"] = len(host)
    feats["path_length"] = len(path)
    feats["query_length"] = len(query)
    feats["fragment_present"] = int(bool(fragment))

    feats["num_dots"] = host.count(".")
    feats["num_hyphens"] = host.count("-")
    feats["num_subdomains"] = max(0, feats["num_dots"] - 1)  # a.b.c.tld -> 3 dots -> 2 subdomains

    feats["has_at_symbol"] = int("@" in urlparse.urlunsplit(("", "", path, query, fragment)))
    feats["double_slash_in_path"] = int("//" in path.strip("/"))
    feats["has_ip_in_host"] = int(_is_ipv4(host))
    feats["has_punycode"] = int(_has_punycode(host))
    feats["digits_ratio_host"] = _digits_ratio(host)
    feats["digits_ratio_path"] = _digits_ratio(path)
    feats["pct_encoded_ratio"] = _pct_encoded_ratio(path + "?" + query)

    feats["suspicious_tld"] = int(tld in SUSPICIOUS_TLDS) if tld else 0

    # Shorteners (exact host match only)
    feats["is_shortener"] = int(registered_domain in URL_SHORTENERS)

    # Keyword flags (in path or query)
    lowered = (path + "?" + query).lower()
    feats["keyword_hits"] = sum(1 for k in PHISH_KEYWORDS if k in lowered)

    # Tokens in path that look like a domain (e.g., paypal.com.login.example.com/path)
    # If the path contains "\\.\\w+\\." it might be trying to spoof a brand inside path
    feats["domain_like_in_path"] = int(bool(re.search(r"[a-z0-9-]+\\.[a-z]{2,}", lowered)))

    # Excessive parameters
    feats["num_params"] = lowered.count("&") + (1 if ("=" in lowered) else 0)

    # Very long TLD or missing suffix
    feats["tld_length"] = len(tld)
    feats["has_tld"] = int(bool(tld))

    # Export a few string fields for explanations
    feats["host"] = host
    feats["registered_domain"] = registered_domain
    feats["tld"] = tld
    feats["scheme"] = scheme
    return feats
