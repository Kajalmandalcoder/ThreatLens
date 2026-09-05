"""
ThreadLens - URL Threat Analyzer & Scoring Engine
Computes heuristic risk score (0-100), categorizes risk level, provides
transparent reasoning, and aggregates metrics across multiple URLs.
"""

from typing import Any, Dict, List, Optional
from url_intelligence.features import (
    extract_sender_root_domain,
    extract_static_features,
    extract_url_components,
    normalize_raw_url,
)


def calculate_url_risk(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes heuristic risk score (0-100) and compiles readable indicators.
    NOTE: This is a transparent rule-based heuristic engine designed to feed
    into the SIH Threat Detection Scoring Model.
    """
    score = 0
    indicators: List[str] = []

    # High-confidence indicators
    if features.get("is_ip_hostname"):
        score += 45
        indicators.append("Hostname is an IP address instead of a domain")

    if features.get("has_at_symbol"):
        score += 40
        indicators.append("URL contains '@' symbol (credential abuse or redirection trick)")

    if features.get("is_punycode"):
        score += 35
        indicators.append("Punycode (IDN) detected: potential homograph attack")

    # Medium-confidence indicators
    if features.get("is_shortener"):
        score += 25
        indicators.append("URL shortening service used to mask destination")

    if features.get("has_excessive_subdomains"):
        score += 20
        indicators.append(
            f"Excessive subdomains ({features.get('subdomain_count')}) often used to hide brand impersonation"
        )

    if features.get("is_http_only"):
        score += 15
        indicators.append("Unencrypted connection (HTTP instead of HTTPS)")

    if features.get("is_unusually_long"):
        score += 15
        indicators.append(
            f"Unusually long URL ({features.get('url_length')} characters)"
        )

    matched_kws = features.get("matched_keywords", [])
    if matched_kws:
        kw_penalty = min(len(matched_kws) * 10, 30)
        score += kw_penalty
        indicators.append(
            f"Suspicious credential/action keywords found in path: {', '.join(matched_kws)}"
        )

    # Low/Contextual indicators
    if features.get("is_sender_mismatch"):
        score += 15
        indicators.append("URL target domain does not match sender domain")

    if features.get("has_hex_encoding"):
        score += 10
        indicators.append("URL contains hexadecimal encoding (%xx)")

    if features.get("has_suspicious_chars"):
        score += 15
        indicators.append("URL contains non-standard or whitespace characters")

    # Cap score between 0 and 100
    final_score = min(max(score, 0), 100)

    # Categorize Risk Level
    if final_score >= 80:
        risk_level = "CRITICAL"
    elif final_score >= 60:
        risk_level = "HIGH"
    elif final_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "indicators": indicators,
    }


def analyze_single_url(
    raw_url_item: Any, sender_root: Optional[str] = None
) -> Dict[str, Any]:
    """
    Performs safe static analysis on one URL. Fails gracefully if malformed.
    """
    url_str = normalize_raw_url(raw_url_item)

    if not url_str:
        return {
            "url": str(raw_url_item),
            "status": "error",
            "error": "Empty or non-string URL input",
            "hostname": None,
            "risk_score": 0,
            "risk_level": "LOW",
            "indicators": ["Malformed or empty URL string"],
            "components": {},
            "features": {},
        }

    components = extract_url_components(url_str)
    if not components.get("is_valid"):
        return {
            "url": url_str,
            "status": "error",
            "error": components.get("error", "Malformed URL structure"),
            "hostname": None,
            "risk_score": 30,
            "risk_level": "MEDIUM",
            "indicators": ["Malformed URL syntax could not be safely parsed"],
            "components": components,
            "features": {},
        }

    features = extract_static_features(components, url_str, sender_root)
    risk_assessment = calculate_url_risk(features)

    return {
        "url": url_str,
        "status": "success",
        "hostname": components.get("hostname"),
        "registered_domain": components.get("registered_domain"),
        "risk_score": risk_assessment["risk_score"],
        "risk_level": risk_assessment["risk_level"],
        "indicators": risk_assessment["indicators"],
        "components": {
            "scheme": components.get("scheme"),
            "port": components.get("port"),
            "path": components.get("path"),
            "query": components.get("query"),
            "fragment": components.get("fragment"),
        },
        "features": features,
        # Plug-in hook for third-party reputation APIs (e.g. VirusTotal, Google Safe Browsing)
        "external_reputation": {
            "provider": None,
            "is_malicious": None,
            "note": "Local static heuristics only (no external API configured)",
        },
    }


def analyze_urls(
    urls: List[Any], sender_email: Optional[str] = None
) -> Dict[str, Any]:
    """
    Public API: Analyzes a collection of extracted URLs and generates an aggregate summary.
    """
    if not isinstance(urls, (list, set, tuple)):
        urls = [urls] if urls else []

    sender_root = extract_sender_root_domain(sender_email)
    url_results: List[Dict[str, Any]] = []

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    max_score = 0

    for item in urls:
        analysis = analyze_single_url(item, sender_root)
        url_results.append(analysis)

        score = analysis["risk_score"]
        if score > max_score:
            max_score = score

        level = analysis["risk_level"]
        if level == "CRITICAL":
            critical_count += 1
        elif level == "HIGH":
            high_count += 1
        elif level == "MEDIUM":
            medium_count += 1
        else:
            low_count += 1

    return {
        "summary": {
            "total_urls": len(url_results),
            "critical_risk_urls": critical_count,
            "high_risk_urls": high_count,
            "medium_risk_urls": medium_count,
            "low_risk_urls": low_count,
            "max_risk_score": max_score,
            "overall_status": (
                "CRITICAL"
                if critical_count > 0
                else "HIGH"
                if high_count > 0
                else "MEDIUM"
                if medium_count > 0
                else "LOW"
            ),
        },
        "urls": url_results,
    }