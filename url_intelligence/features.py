"""
ThreadLens - URL Intelligence Feature Extraction
Static and heuristic feature extractors for suspicious URL detection.
Safe by design: Performs zero network requests or URL dereferencing.
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse
import tldextract

# Known URL shorteners often leveraged in phishing campaigns
KNOWN_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "bit.do",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "tiny.cc",
}

# High-risk path/query tokens frequently seen in credential harvesting
SUSPICIOUS_PATH_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "authenticate",
    "account",
    "password",
    "credential",
    "banking",
    "payment",
    "secure",
    "update",
    "confirm",
    "wallet",
}


def normalize_raw_url(raw_input: Any) -> Optional[str]:
    """Safely extracts and strips string URL whether input is str or dict."""
    if not raw_input:
        return None
    if isinstance(raw_input, dict):
        raw_input = (
            raw_input.get("url")
            or raw_input.get("href")
            or raw_input.get("link")
            or ""
        )
    if not isinstance(raw_input, str):
        return None
    cleaned = raw_input.strip()
    return cleaned if cleaned else None


def extract_url_components(url: str) -> Dict[str, Any]:
    """
    Safely parses URL into structural components without network interaction.
    """
    try:
        # Prepend scheme if missing so urlparse extracts netloc properly
        target_url = url
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target_url):
            target_url = "http://" + target_url

        parsed = urlparse(target_url)
        hostname = (parsed.hostname or "").lower()

        # Extract registered root domain safely across all tldextract versions
        ext = tldextract.extract(hostname)
        raw_reg = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
        reg_domain = raw_reg.lower() if raw_reg else None

        return {
            "scheme": parsed.scheme.lower() if parsed.scheme else "unknown",
            "hostname": hostname,
            "registered_domain": reg_domain,
            "port": parsed.port,
            "path": parsed.path or "",
            "query": parsed.query or "",
            "fragment": parsed.fragment or "",
            "username": parsed.username,
            "password": parsed.password,
            "is_valid": bool(hostname),
        }
    except Exception as exc:
        return {
            "scheme": "invalid",
            "hostname": "",
            "registered_domain": None,
            "port": None,
            "path": "",
            "query": "",
            "fragment": "",
            "username": None,
            "password": None,
            "is_valid": False,
            "error": str(exc),
        }


def extract_sender_root_domain(sender_email: Optional[str]) -> Optional[str]:
    """Resolves root registered domain from sender email address."""
    if not sender_email or "@" not in sender_email:
        return None
    try:
        domain_part = sender_email.split("@")[-1].strip().rstrip(">").lower()
        ext = tldextract.extract(domain_part)
        raw_reg = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
        return raw_reg.lower() if raw_reg else None
    except Exception:
        return None


def extract_static_features(
    components: Dict[str, Any], raw_url: str, sender_root_domain: Optional[str] = None
) -> Dict[str, Any]:
    """
    Extracts heuristic signals and flags from normalized components.
    """
    hostname = components.get("hostname", "")
    scheme = components.get("scheme", "")
    path = components.get("path", "").lower()
    query = components.get("query", "").lower()

    # 1. Scheme Check
    is_http_only = scheme == "http"

    # 2. IP as Hostname Check
    is_ip_hostname = False
    if hostname:
        try:
            ipaddress.ip_address(hostname)
            is_ip_hostname = True
        except ValueError:
            is_ip_hostname = False

    # 3. URL Shortener Detection
    is_shortener = components.get("registered_domain") in KNOWN_SHORTENERS

    # 4. Excessive Subdomains (e.g., login.verify.secure.paypal.com.attacker.com)
    # Count subdomains by splitting hostname dots excluding root domain
    subdomain_count = 0
    if hostname:
        parts = hostname.split(".")
        if len(parts) > 2:
            subdomain_count = len(parts) - 2
    has_excessive_subdomains = subdomain_count >= 3

    # 5. Length checks
    url_length = len(raw_url)
    is_unusually_long = url_length > 100

    # 6. Embedded Credential / @ symbol trick
    has_at_symbol = "@" in raw_url.split("?")[0]

    # 7. Suspicious encoding or non-standard characters
    has_hex_encoding = bool(re.search(r"%[0-9a-fA-F]{2}", raw_url))
    has_suspicious_chars = bool(re.search(r"[\s\x00-\x1f\x7f]", raw_url))

    # 8. Punycode / IDN detection
    is_punycode = "xn--" in hostname

    # 9. Suspicious path/query keywords
    full_path_query = f"{unquote(path)}?{unquote(query)}"
    matched_keywords: List[str] = []
    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if re.search(rf"\b{re.escape(kw)}\b", full_path_query):
            matched_keywords.append(kw)

    # 10. Sender Domain Mismatch
    url_root = components.get("registered_domain")
    is_sender_mismatch = False
    if sender_root_domain and url_root:
        is_sender_mismatch = sender_root_domain != url_root

    return {
        "url_length": url_length,
        "is_http_only": is_http_only,
        "is_ip_hostname": is_ip_hostname,
        "is_shortener": is_shortener,
        "subdomain_count": subdomain_count,
        "has_excessive_subdomains": has_excessive_subdomains,
        "is_unusually_long": is_unusually_long,
        "has_at_symbol": has_at_symbol,
        "has_hex_encoding": has_hex_encoding,
        "has_suspicious_chars": has_suspicious_chars,
        "is_punycode": is_punycode,
        "matched_keywords": matched_keywords,
        "is_sender_mismatch": is_sender_mismatch,
    }