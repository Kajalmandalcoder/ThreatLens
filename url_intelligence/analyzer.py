"""
ThreadLens - URL Threat Analyzer & Scoring Engine

Computes heuristic risk score (0-100), categorizes risk level,
provides transparent reasoning, and aggregates metrics across URLs.
"""

import json
import sys
from typing import Any, Dict, List, Optional

from url_intelligence.features import (
    extract_sender_root_domain,
    extract_static_features,
    extract_url_components,
    normalize_raw_url,
)


def calculate_url_risk(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes heuristic risk score (0-100)
    and compiles readable indicators.
    """

    score = 0
    indicators: List[str] = []

    # =========================================
    # HIGH CONFIDENCE INDICATORS
    # =========================================

    if features.get("is_ip_hostname"):
        score += 45
        indicators.append(
            "Hostname is an IP address instead of a domain"
        )

    if features.get("has_at_symbol"):
        score += 40
        indicators.append(
            "URL contains '@' symbol (credential abuse or redirection trick)"
        )

    if features.get("is_punycode"):
        score += 35
        indicators.append(
            "Punycode (IDN) detected: potential homograph attack"
        )

    # =========================================
    # MEDIUM CONFIDENCE INDICATORS
    # =========================================

    if features.get("is_shortener"):
        score += 25
        indicators.append(
            "URL shortening service used to mask destination"
        )

    if features.get("has_excessive_subdomains"):
        score += 20
        indicators.append(
            f"Excessive subdomains ({features.get('subdomain_count')}) "
            "often used to hide brand impersonation"
        )

    if features.get("is_http_only"):
        score += 15
        indicators.append(
            "Unencrypted connection (HTTP instead of HTTPS)"
        )

    if features.get("is_unusually_long"):
        score += 15
        indicators.append(
            f"Unusually long URL ({features.get('url_length')} characters)"
        )

    matched_kws = features.get("matched_keywords", [])

    if matched_kws:
        keyword_penalty = min(len(matched_kws) * 10, 30)
        score += keyword_penalty

        indicators.append(
            "Suspicious credential/action keywords found in path: "
            + ", ".join(matched_kws)
        )

    # =========================================
    # CONTEXTUAL INDICATORS
    # =========================================

    if features.get("is_sender_mismatch"):
        score += 15
        indicators.append(
            "URL target domain does not match sender domain"
        )

    if features.get("has_hex_encoding"):
        score += 10
        indicators.append(
            "URL contains hexadecimal encoding (%xx)"
        )

    if features.get("has_suspicious_chars"):
        score += 15
        indicators.append(
            "URL contains non-standard or whitespace characters"
        )

    # =========================================
    # CAP SCORE
    # =========================================

    final_score = min(max(score, 0), 100)

    # =========================================
    # RISK LEVEL
    # =========================================

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
    raw_url_item: Any,
    sender_root: Optional[str] = None
) -> Dict[str, Any]:
    """
    Performs safe static analysis on one URL.
    """

    url_str = normalize_raw_url(raw_url_item)

    # =========================================
    # EMPTY / INVALID INPUT
    # =========================================

    if not url_str:
        return {
            "url": str(raw_url_item),
            "status": "error",
            "error": "Empty or non-string URL input",
            "hostname": None,
            "registered_domain": None,
            "risk_score": 0,
            "risk_level": "LOW",
            "indicators": [
                "Malformed or empty URL string"
            ],
            "components": {},
            "features": {},
        }

    # =========================================
    # PARSE URL
    # =========================================

    components = extract_url_components(url_str)

    if not components.get("is_valid"):

        return {
            "url": url_str,
            "status": "error",
            "error": components.get(
                "error",
                "Malformed URL structure"
            ),
            "hostname": None,
            "registered_domain": None,
            "risk_score": 30,
            "risk_level": "MEDIUM",
            "indicators": [
                "Malformed URL syntax could not be safely parsed"
            ],
            "components": components,
            "features": {},
        }

    # =========================================
    # FEATURE EXTRACTION
    # =========================================

    features = extract_static_features(
        components,
        url_str,
        sender_root
    )

    # =========================================
    # RISK CALCULATION
    # =========================================

    risk_assessment = calculate_url_risk(features)

    # =========================================
    # RESULT
    # =========================================

    return {
        "url": url_str,
        "status": "success",
        "hostname": components.get("hostname"),
        "registered_domain": components.get(
            "registered_domain"
        ),
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

        # No external API currently configured
        "external_reputation": {
            "provider": None,
            "is_malicious": None,
            "note": (
                "Local static heuristics only "
                "(no external API configured)"
            ),
        },
    }


def analyze_urls(
    urls: List[Any],
    sender_email: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyzes a collection of URLs and generates
    aggregate URL Intelligence summary.
    """

    if not isinstance(urls, (list, set, tuple)):
        urls = [urls] if urls else []

    # =========================================
    # GET SENDER ROOT DOMAIN
    # =========================================

    sender_root = extract_sender_root_domain(
        sender_email
    )

    url_results: List[Dict[str, Any]] = []

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    max_score = 0

    # =========================================
    # ANALYZE EVERY URL
    # =========================================

    for item in urls:

        analysis = analyze_single_url(
            item,
            sender_root
        )

        url_results.append(analysis)

        score = analysis.get(
            "risk_score",
            0
        )

        max_score = max(
            max_score,
            score
        )

        level = analysis.get(
            "risk_level",
            "LOW"
        )

        if level == "CRITICAL":
            critical_count += 1

        elif level == "HIGH":
            high_count += 1

        elif level == "MEDIUM":
            medium_count += 1

        else:
            low_count += 1

    # =========================================
    # OVERALL STATUS
    # =========================================

    if critical_count > 0:
        overall_status = "CRITICAL"

    elif high_count > 0:
        overall_status = "HIGH"

    elif medium_count > 0:
        overall_status = "MEDIUM"

    else:
        overall_status = "LOW"

    # =========================================
    # FINAL RESULT
    # =========================================

    return {
        "summary": {
            "total_urls": len(url_results),
            "critical_risk_urls": critical_count,
            "high_risk_urls": high_count,
            "medium_risk_urls": medium_count,
            "low_risk_urls": low_count,
            "max_risk_score": max_score,
            "overall_status": overall_status,
        },

        "urls": url_results,
    }


# ============================================================
# CLI ENTRY POINT
# Node.js will send JSON through stdin
# ============================================================

if __name__ == "__main__":

    try:

        input_data = json.loads(
            sys.stdin.read()
        )

        urls = input_data.get(
            "urls",
            []
        )

        sender_email = input_data.get(
            "sender_email"
        )

        result = analyze_urls(
            urls,
            sender_email
        )

        print(
            json.dumps(
                result,
                ensure_ascii=False
            )
        )

    except Exception as exc:

        print(
            json.dumps({
                "error": str(exc)
            })
        )

        sys.exit(1)