"""
ThreadLens - Domain Intelligence Module
Analyzes sender identities, lookalike domains, MX records, and body link mismatches.
"""

import difflib
import json
import os
import re
from typing import Any, Dict, List, Optional
import dns.resolver
import tldextract


# Load static brand list safely
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BRAND_TARGETS_FILE = os.path.join(CURRENT_DIR, "brand_targets.json")

def load_brand_targets() -> List[str]:
    if os.path.exists(BRAND_TARGETS_FILE):
        try:
            with open(BRAND_TARGETS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return ["paypal", "microsoft", "google", "apple", "amazon"]


def extract_email_address(raw_header: Optional[str]) -> Optional[str]:
    """Extract raw email address from header strings like 'Name <user@domain.com>'."""
    if not raw_header or not isinstance(raw_header, str):
        return None
    match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", raw_header)
    return match.group(0).lower() if match else None


def extract_domain_parts(domain_or_email: Any) -> Dict[str, Optional[str]]:
    """Parse domain into registered domain, domain name (SLD), and suffix."""
    empty = {"registered_domain": None, "domain_name": None, "suffix": None}
    if not domain_or_email:
        return empty

    # Handle cases where links are stored as dicts (e.g., {"url": "...", "text": "..."})
    raw_target = domain_or_email
    if isinstance(raw_target, dict):
        raw_target = (
            raw_target.get("url")
            or raw_target.get("href")
            or raw_target.get("link")
            or ""
        )

    if not isinstance(raw_target, str) or not raw_target.strip():
        return empty

    raw_target = raw_target.strip()
    target = extract_email_address(raw_target) or raw_target.lower()

    try:
        extracted = tldextract.extract(target)
        if not extracted.domain or not extracted.suffix:
            return empty

        reg_domain = (
            getattr(extracted, "top_domain_under_public_suffix", None)
            or extracted.registered_domain
        )

        return {
            "registered_domain": reg_domain,
            "domain_name": extracted.domain,
            "suffix": extracted.suffix,
        }
    except Exception:
        return empty


def check_mx_record(domain: str, timeout_sec: float = 2.0) -> bool:
    """Verify if a domain has active MX records."""
    if not domain:
        return False
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout_sec
    try:
        answers = resolver.resolve(domain, "MX")
        return len(answers) > 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
        return False


LEET_TRANSLATIONS = str.maketrans({
    "1": "l",
    "0": "o",
    "3": "e",
    "5": "s",
    "8": "b",
    "@": "a",
})

def detect_lookalike_brand(domain_name: str, brand_list: List[str], threshold: float = 0.8) -> Dict[str, Any]:
    """
    Check if the domain name or any of its hyphenated tokens is a lookalike/typosquat
    of a protected brand using homoglyph mapping and sequence matching.
    """
    if not domain_name:
        return {"is_lookalike": False, "matched_brand": None, "similarity": 0.0}

    domain_clean = domain_name.lower().replace("vv", "w")
    
    # 1-to-1 leet-character normalization
    normalized_candidate = domain_clean.translate(LEET_TRANSLATIONS)

    # Split compound slugs into tokens (e.g. "paypa1-security" -> ["paypa1", "security", "paypal", ...])
    tokens = set(domain_clean.split("-") + normalized_candidate.split("-") + [domain_clean, normalized_candidate])

    for brand in brand_list:
        brand_clean = brand.lower()

        # Legitimate brand itself is not a lookalike
        if domain_clean == brand_clean:
            return {"is_lookalike": False, "matched_brand": brand, "similarity": 1.0}

        for token in tokens:
            if not token:
                continue

            # Exact token match after leet normalization (e.g. "paypa1" -> "paypal")
            if token == brand_clean and domain_clean != brand_clean:
                return {
                    "is_lookalike": True,
                    "matched_brand": brand,
                    "similarity": 0.95,
                }

            # Fuzzy sequence similarity
            ratio = difflib.SequenceMatcher(None, token, brand_clean).ratio()
            if ratio >= threshold and token != brand_clean:
                return {
                    "is_lookalike": True,
                    "matched_brand": brand,
                    "similarity": round(ratio, 2),
                }

    return {"is_lookalike": False, "matched_brand": None, "similarity": 0.0}


def analyze_domain_intelligence(
    from_header: Optional[str],
    reply_to_header: Optional[str] = None,
    return_path_header: Optional[str] = None,
    body_urls: Optional[List[str]] = None,
    offline_mode: bool = False,
) -> Dict[str, Any]:
    """
    Main entry point for Domain Intelligence.
    Consumes header forensic domain data and body URLs, producing structured risk signals.
    """
    body_urls = body_urls or []
    brand_targets = load_brand_targets()

    from_parts = extract_domain_parts(from_header)
    reply_to_parts = extract_domain_parts(reply_to_header)
    return_path_parts = extract_domain_parts(return_path_header)

    from_domain = from_parts["registered_domain"]
    reply_to_domain = reply_to_parts["registered_domain"]
    return_path_domain = return_path_parts["registered_domain"]

    # Extract registered domains from body URLs
    body_domains = set()
    for url in body_urls:
        parts = extract_domain_parts(url)
        if parts["registered_domain"]:
            body_domains.add(parts["registered_domain"])

    # Lookalike Brand Check
    lookalike_info = detect_lookalike_brand(from_parts["domain_name"] or "", brand_targets)

    # Header Alignment
    reply_to_mismatch = bool(
        reply_to_domain and from_domain and reply_to_domain != from_domain
    )
    return_path_mismatch = bool(
        return_path_domain and from_domain and return_path_domain != from_domain
    )

    # Body Link Alignment: flag if links exist and none match the sender domain
    body_domain_mismatch = False
    if from_domain and body_domains:
        body_domain_mismatch = from_domain not in body_domains

    # Live MX Check
    has_mx = True
    if from_domain and not offline_mode:
        has_mx = check_mx_record(from_domain)

    return {
        "status": "success",
        "domains": {
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
            "body_domains": sorted(list(body_domains)),
        },
        "identity_alignment": {
            "from_matches_reply_to": not reply_to_mismatch,
            "from_matches_return_path": not return_path_mismatch,
            "from_matches_body_links": not body_domain_mismatch,
        },
        "lookalike_analysis": lookalike_info,
        "dns_health": {
            "from_has_mx": has_mx,
        },
        "signals": {
            "reply_to_mismatch": reply_to_mismatch,
            "return_path_mismatch": return_path_mismatch,
            "is_brand_lookalike": lookalike_info["is_lookalike"],
            "body_domain_mismatch": body_domain_mismatch,
            "from_missing_mx": not has_mx,
        },
    }