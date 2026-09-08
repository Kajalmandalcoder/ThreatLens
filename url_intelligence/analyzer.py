"""ThreadLens - URL Threat Analyzer & Scoring Engine."""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import sys
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from url_intelligence.features import (
    extract_sender_root_domain,
    extract_static_features,
    extract_url_components,
    normalize_raw_url,
)


# ============================================================
# ENVIRONMENT
# ============================================================

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

if load_dotenv is not None:
    for env_file in (
        os.path.join(PROJECT_ROOT, "backend", ".env"),
        os.path.join(PROJECT_ROOT, ".env"),
    ):
        if os.path.exists(env_file):
            load_dotenv(env_file, override=True)
            break


# ============================================================
# CONFIG
# ============================================================

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_URLS_ENDPOINT = "https://www.virustotal.com/api/v3/urls/{}"

try:
    URL_REQUEST_TIMEOUT = float(os.getenv("URL_REQUEST_TIMEOUT", "5.0"))
except (TypeError, ValueError):
    URL_REQUEST_TIMEOUT = 5.0

try:
    MAX_REDIRECTS = max(0, int(os.getenv("URL_MAX_REDIRECTS", "5")))
except (TypeError, ValueError):
    MAX_REDIRECTS = 5


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


ENABLE_REDIRECT_ANALYSIS = _env_bool("URL_ENABLE_REDIRECT_ANALYSIS", True)
BLOCK_PRIVATE_REDIRECTS = _env_bool("URL_BLOCK_PRIVATE_REDIRECTS", True)


# ============================================================
# BENIGN / INFRASTRUCTURE CONTEXT
# ============================================================

BENIGN_INFRASTRUCTURE_DOMAINS = {
    "google.com",
    "googleapis.com",
    "googleusercontent.com",
    "gstatic.com",
    "microsoft.com",
    "microsoftonline.com",
    "live.com",
    "office.com",
    "office365.com",
    "apple.com",
    "icloud.com",
    "linkedin.com",
    "licdn.com",
    "w3.org",
    "amazon.com",
    "amazonaws.com",
    "cloudfront.net",
    "akamaihd.net",
    "fastly.net",
    "github.com",
    "githubusercontent.com",
    "outlook.com",
    "facebook.com",
    "instagram.com",
    "youtube.com",
    "youtu.be",
    "webengage.com",
}

BENIGN_ASSET_HOST_PREFIXES = (
    "static.",
    "media.",
    "images.",
    "img.",
    "cdn.",
    "assets.",
    "fonts.",
    "ci3.",
)


# ============================================================
# HELPERS
# ============================================================


def _domain(value: Optional[str]) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


def _is_benign_infrastructure_domain(
    registered_domain: Optional[str],
    hostname: Optional[str],
    path: str = "",
) -> bool:
    domain = _domain(registered_domain)
    host = _domain(hostname)

    if domain in BENIGN_INFRASTRUCTURE_DOMAINS:
        return True

    if any(host.startswith(prefix) for prefix in BENIGN_ASSET_HOST_PREFIXES):
        return bool(domain)

    return False


def _looks_like_static_asset_url(hostname: Optional[str], path: str) -> bool:
    host = _domain(hostname)
    path_lower = path.lower() if isinstance(path, str) else ""

    if any(host.startswith(prefix) for prefix in BENIGN_ASSET_HOST_PREFIXES):
        return True

    return any(
        marker in path_lower
        for marker in (
            "/static/",
            "/assets/",
            "/images/",
            "/image/",
            "/mail-sig/",
            "/aero-v1/",
            "/fonts/",
            "/css/",
            "/js/",
            "/store/",
            "/lw/g1.jpg",
        )
    )


def _is_legitimate_tracking_context(
    registered_domain: Optional[str],
    hostname: Optional[str],
    path: str,
    query: str,
) -> bool:
    domain = _domain(registered_domain)
    host = _domain(hostname)
    path_lower = path.lower() if isinstance(path, str) else ""
    query_lower = query.lower() if isinstance(query, str) else ""

    legitimate_domains = {
        "linkedin.com",
        "google.com",
        "microsoft.com",
        "apple.com",
        "webengage.com",
    }

    if domain in legitimate_domains:
        if any(
            marker in query_lower
            for marker in ("utm_", "lipi=", "referrer=", "cid=", "event=")
        ):
            return True

    if any(host.startswith(prefix) for prefix in BENIGN_ASSET_HOST_PREFIXES):
        return True

    if domain == "webengage.com" and any(
        marker in path_lower for marker in ("/lw/g1.jpg", "/unsubscribe", "/track/")
    ):
        return True

    return False


def _is_private_or_special_hostname(hostname: Optional[str]) -> bool:
    host = _domain(hostname)
    if not host:
        return True

    if host in {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "0.0.0.0",
    }:
        return True

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _disabled_reputation() -> Dict[str, Any]:
    return {
        "reputation_status": "disabled",
        "provider": "VirusTotal",
        "is_malicious": None,
        "malicious_detections": None,
        "suspicious_detections": None,
        "total_detections": None,
        "malicious_ratio": None,
        "reputation_score": None,
    }


def _disabled_redirect() -> Dict[str, Any]:
    return {
        "status": "disabled",
        "redirected": False,
        "redirect_count": 0,
        "chain": [],
        "final_url": None,
        "final_hostname": None,
        "error": None,
    }


# ============================================================
# VIRUSTOTAL
# ============================================================


def _encode_url_for_virustotal(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def enrich_url_reputation(
    url: Optional[str],
    timeout_sec: float = URL_REQUEST_TIMEOUT,
) -> Dict[str, Any]:
    result = {
        "reputation_status": "unavailable",
        "provider": "VirusTotal",
        "is_malicious": None,
        "malicious_detections": None,
        "suspicious_detections": None,
        "total_detections": None,
        "malicious_ratio": None,
        "reputation_score": None,
    }

    if not url:
        result["reputation_status"] = "url_missing"
        return result

    if not VIRUSTOTAL_API_KEY:
        result["reputation_status"] = "api_key_missing"
        return result

    try:
        endpoint = VIRUSTOTAL_URLS_ENDPOINT.format(_encode_url_for_virustotal(url))
        response = requests.get(
            endpoint,
            headers={
                "x-apikey": VIRUSTOTAL_API_KEY,
                "Accept": "application/json",
            },
            timeout=timeout_sec,
        )

        if response.status_code != 200:
            result["reputation_status"] = f"http_{response.status_code}"
            return result

        payload = response.json()
        data = payload.get("data") or {}
        attributes = data.get("attributes") or {}
        stats = attributes.get("last_analysis_stats")

        if not isinstance(stats, dict):
            result["reputation_status"] = "invalid_analysis_stats"
            return result

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        timeout_count = stats.get("timeout", 0)

        values = [malicious, suspicious, harmless, undetected, timeout_count]
        total = sum(
            int(value)
            for value in values
            if isinstance(value, int) and not isinstance(value, bool)
        )

        if total <= 0:
            result["reputation_status"] = "no_analysis_data"
            return result

        try:
            min_ratio = float(os.getenv("VT_URL_MALICIOUS_MIN_RATIO", "0.10"))
        except (TypeError, ValueError):
            min_ratio = 0.10

        try:
            min_detections = max(
                1, int(os.getenv("VT_URL_MALICIOUS_MIN_DETECTIONS", "3"))
            )
        except (TypeError, ValueError):
            min_detections = 3

        ratio = malicious / total
        is_malicious = bool(
            malicious >= min_detections and ratio >= min_ratio
        )

        return {
            "reputation_status": "success",
            "provider": "VirusTotal",
            "is_malicious": is_malicious,
            "malicious_detections": malicious,
            "suspicious_detections": suspicious,
            "total_detections": total,
            "malicious_ratio": round(ratio, 4),
            "reputation_score": round(ratio * 100, 2),
        }

    except requests.Timeout:
        result["reputation_status"] = "network_timeout_or_error"
        return result
    except requests.RequestException:
        result["reputation_status"] = "network_timeout_or_error"
        return result
    except (ValueError, TypeError):
        result["reputation_status"] = "invalid_api_response"
        return result
    except Exception:
        result["reputation_status"] = "unexpected_error"
        return result


# ============================================================
# REDIRECT ANALYSIS
# ============================================================


def analyze_redirect_chain(
    url: Optional[str],
    timeout_sec: float = URL_REQUEST_TIMEOUT,
) -> Dict[str, Any]:
    result = {
        "status": "not_attempted",
        "redirected": False,
        "redirect_count": 0,
        "chain": [],
        "final_url": None,
        "final_hostname": None,
        "error": None,
    }

    if not url:
        result["status"] = "url_missing"
        return result

    if not ENABLE_REDIRECT_ANALYSIS:
        result["status"] = "disabled"
        return result

    try:
        current_url = url
        chain: List[Dict[str, Any]] = []
        session = requests.Session()
        session.headers.update({"User-Agent": "ThreadLens-URL-Analyzer/1.0"})

        for _ in range(MAX_REDIRECTS + 1):
            parsed = urlparse(current_url)
            current_hostname = parsed.hostname

            if BLOCK_PRIVATE_REDIRECTS and _is_private_or_special_hostname(
                current_hostname
            ):
                result.update(
                    {
                        "status": "blocked_private_destination",
                        "redirected": len(chain) > 1,
                        "redirect_count": max(len(chain) - 1, 0),
                        "chain": chain,
                        "final_url": current_url,
                        "final_hostname": current_hostname,
                        "error": (
                            "Redirect analysis blocked for "
                            "private/local/special destination"
                        ),
                    }
                )
                return result

            response = session.get(
                current_url,
                allow_redirects=False,
                timeout=timeout_sec,
                stream=True,
            )

            location = response.headers.get("Location")
            chain.append(
                {
                    "url": current_url,
                    "status_code": response.status_code,
                    "location": location,
                }
            )
            response.close()

            if response.is_redirect or response.is_permanent_redirect:
                if not location:
                    break
                next_url = urljoin(current_url, location)
                if not next_url:
                    break
                current_url = next_url
                continue

            break

        final_url = chain[-1]["url"] if chain else url
        final_hostname = None
        try:
            final_hostname = urlparse(final_url).hostname
        except Exception:
            pass

        return {
            "status": "success",
            "redirected": len(chain) > 1,
            "redirect_count": max(len(chain) - 1, 0),
            "chain": chain,
            "final_url": final_url,
            "final_hostname": final_hostname,
            "error": None,
        }

    except requests.Timeout:
        result["status"] = "network_timeout_or_error"
        result["error"] = "Request timed out"
        return result
    except requests.RequestException as exc:
        result["status"] = "network_error"
        result["error"] = str(exc)
        return result
    except Exception as exc:
        result["status"] = "analysis_error"
        result["error"] = str(exc)
        return result


# ============================================================
# HISTORY
# ============================================================


def _extract_case_url(case: Dict[str, Any]) -> List[str]:
    values: List[str] = []

    url_intelligence = case.get("urlIntelligence")
    if isinstance(url_intelligence, dict):
        urls = url_intelligence.get("urls", [])
        if isinstance(urls, list):
            for item in urls:
                if isinstance(item, dict) and item.get("url"):
                    values.append(str(item["url"]))

    direct_urls = case.get("urls")
    if isinstance(direct_urls, list):
        for item in direct_urls:
            if isinstance(item, str):
                values.append(item)
            elif isinstance(item, dict) and item.get("url"):
                values.append(str(item["url"]))

    return values


def _canonical_url_for_history(url: str) -> str:
    normalized = normalize_raw_url(url) or url
    return normalized.strip().lower()


def correlate_url_with_previous_cases(
    url: Optional[str],
    previous_cases: Optional[Iterable[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    if not url:
        return {
            "history_status": "url_missing",
            "historical_match": None,
            "matching_case_ids": [],
            "match_count": 0,
        }

    if previous_cases is None:
        return {
            "history_status": "not_provided",
            "historical_match": None,
            "matching_case_ids": [],
            "match_count": 0,
        }

    target = _canonical_url_for_history(url)
    matching_case_ids: List[str] = []

    for case in previous_cases:
        if not isinstance(case, dict):
            continue

        case_id = case.get("caseId")
        for case_url in _extract_case_url(case):
            if _canonical_url_for_history(case_url) == target:
                if case_id:
                    matching_case_ids.append(str(case_id))
                break

    matching_case_ids = sorted(set(matching_case_ids))
    return {
        "history_status": "success",
        "historical_match": bool(matching_case_ids),
        "matching_case_ids": matching_case_ids,
        "match_count": len(matching_case_ids),
    }


# ============================================================
# RISK SCORING
# ============================================================


def calculate_url_risk(
    features: Dict[str, Any],
    reputation: Optional[Dict[str, Any]] = None,
    redirect_analysis: Optional[Dict[str, Any]] = None,
    historical_correlation: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    score = 0
    indicators: List[str] = []

    hostname = features.get("hostname")
    registered_domain = features.get("registered_domain")
    path = features.get("path", "") or ""
    query = features.get("query", "") or ""

    benign_infra = _is_benign_infrastructure_domain(
        registered_domain, hostname, path
    )
    static_asset = _looks_like_static_asset_url(hostname, path)
    legitimate_tracking = _is_legitimate_tracking_context(
        registered_domain, hostname, path, query
    )

    # Strong reputation signal.
    if reputation and reputation.get("is_malicious") is True:
        score += 60
        malicious = reputation.get("malicious_detections")
        total = reputation.get("total_detections")
        if malicious is not None and total:
            indicators.append(
                f"Strong malicious URL reputation ({malicious}/{total} scanners)"
            )
        else:
            indicators.append("URL flagged as malicious by reputation intelligence")

    if features.get("is_ip_hostname"):
        score += 45
        indicators.append("Hostname is an IP address instead of a domain")

    if features.get("has_at_symbol"):
        score += 40
        indicators.append("URL contains '@' in the authority section")

    if features.get("is_punycode"):
        score += 35
        indicators.append("Punycode (IDN) detected: potential homograph risk")

    if features.get("is_defanged"):
        score += 10
        indicators.append("Defanged URL notation detected")

    if features.get("is_shortener"):
        score += 15
        indicators.append("Known URL shortening service used")

    if features.get("has_excessive_subdomains"):
        score += 15
        indicators.append(
            f"Excessive subdomains ({features.get('subdomain_count')})"
        )

    if features.get("suspicious_tld"):
        score += 15
        tld = features.get("tld")
        indicators.append(
            f"Domain uses suspicious TLD .{tld}"
            if tld
            else "Domain uses suspicious top-level domain"
        )

    if features.get("has_suspicious_fragment") and not (
        benign_infra or legitimate_tracking
    ):
        score += 15
        indicators.append(
            "URL fragment contains redirect, tracking, or token-like structure"
        )

    if features.get("has_tracking_path") and not (
        benign_infra or legitimate_tracking
    ):
        score += 10
        indicators.append("URL contains tracking or redirect path structure")

    if features.get("has_obfuscated_path") and not static_asset:
        score += 10
        indicators.append("URL path contains potentially obfuscated data")

    if features.get("is_http_only"):
        score += 5
        indicators.append("URL uses unencrypted HTTP")

    matched_keywords = features.get("matched_keywords") or []
    if matched_keywords and not benign_infra:
        score += min(len(matched_keywords) * 5, 15)
        indicators.append(
            "Credential/action keywords detected: " + ", ".join(matched_keywords)
        )

    if features.get("is_unusually_long") and not (
        benign_infra or static_asset or legitimate_tracking
    ):
        score += 5
        indicators.append(
            f"Unusually long URL ({features.get('url_length')} characters)"
        )

    if features.get("has_suspicious_chars"):
        score += 10
        indicators.append("URL contains whitespace or control characters")

    if features.get("has_hex_encoding") and not legitimate_tracking:
        score += 2
        indicators.append("URL contains percent-encoded characters")

    # Mismatch is evidence, not risk by itself.
    if features.get("is_sender_mismatch") and not benign_infra:
        indicators.append("URL target is external to the sender domain")

    if redirect_analysis and redirect_analysis.get("redirected") is True:
        count = int(redirect_analysis.get("redirect_count") or 0)
        if count > 0 and not (benign_infra or legitimate_tracking):
            score += 5
            indicators.append(f"URL redirects through {count} hop(s)")

    if historical_correlation and historical_correlation.get("historical_match") is True:
        score += 15
        count = int(historical_correlation.get("match_count") or 0)
        indicators.append(f"Exact URL appeared in previous ThreadLens case(s) ({count})")

    # Combination boost.
    combination_score = 0
    if features.get("is_shortener") and features.get("has_tracking_path"):
        combination_score += 10
    if features.get("is_shortener") and features.get("is_unusually_long"):
        combination_score += 5
    if features.get("is_ip_hostname") and features.get("has_at_symbol"):
        combination_score += 15
    if features.get("is_punycode") and features.get("has_at_symbol"):
        combination_score += 15
    if (
        matched_keywords
        and features.get("is_sender_mismatch")
        and not benign_infra
    ):
        combination_score += 5
    if (
        features.get("has_suspicious_fragment")
        and features.get("is_sender_mismatch")
        and not benign_infra
    ):
        combination_score += 5
    if features.get("is_defanged") and (
        features.get("is_shortener")
        or features.get("is_ip_hostname")
        or features.get("has_at_symbol")
    ):
        combination_score += 10

    if combination_score:
        score += min(combination_score, 25)
        indicators.append("Multiple correlated URL risk indicators detected")

    # Credential/payment context boost.
    credential_keywords = {
        "login", "log-in", "signin", "sign-in", "verify", "verification",
        "authenticate", "authentication", "password", "credential",
        "credentials", "banking", "payment", "billing", "wallet", "recover",
        "recovery", "unlock", "suspend", "suspended", "reset", "validate",
        "authorization", "authorize", "otp", "mfa", "2fa",
    }
    matched_credential_keywords = [
        keyword for keyword in matched_keywords if keyword in credential_keywords
    ]

    phishing_context = 0
    if matched_credential_keywords:
        if features.get("is_sender_mismatch"):
            phishing_context += 10
        if features.get("is_shortener"):
            phishing_context += 15
        if features.get("is_ip_hostname"):
            phishing_context += 15
        if features.get("has_at_symbol"):
            phishing_context += 15
        if features.get("is_punycode"):
            phishing_context += 15
        if features.get("is_defanged"):
            phishing_context += 10
        if features.get("has_tracking_path"):
            phishing_context += 5

    if phishing_context:
        score += min(phishing_context, 30)
        indicators.append(
            "Credential/payment-related URL appears in a higher-risk external context"
        )

    final_score = min(max(score, 0), 100)
    if final_score >= 80:
        risk_level = "CRITICAL"
    elif final_score >= 60:
        risk_level = "HIGH"
    elif final_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Deduplicate indicators while preserving order.
    indicators = list(dict.fromkeys(indicators))

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "indicators": indicators,
    }


# ============================================================
# SINGLE URL ANALYSIS
# ============================================================


def analyze_single_url(
    raw_url_item: Any,
    sender_root: Optional[str] = None,
    previous_cases: Optional[Iterable[Dict[str, Any]]] = None,
    enable_reputation: bool = True,
    enable_redirect_analysis: bool = True,
) -> Dict[str, Any]:
    original_url: Optional[str] = None

    if isinstance(raw_url_item, str):
        original_url = raw_url_item.strip()
    elif isinstance(raw_url_item, dict):
        value = (
            raw_url_item.get("url")
            or raw_url_item.get("href")
            or raw_url_item.get("link")
        )
        if isinstance(value, str):
            original_url = value.strip()

    url_str = normalize_raw_url(raw_url_item)
    if not url_str:
        return {
            "url": str(raw_url_item),
            "status": "error",
            "error": "Empty or non-string URL input",
            "hostname": None,
            "registered_domain": None,
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "indicators": ["Malformed or empty URL string"],
            "components": {},
            "features": {},
            "external_reputation": {
                "provider": "VirusTotal",
                "is_malicious": None,
                "reputation_status": "url_missing",
            },
            "redirect_analysis": {"status": "url_missing"},
            "historical_correlation": {
                "history_status": "url_missing",
                "historical_match": None,
                "matching_case_ids": [],
                "match_count": 0,
            },
            "normalized_output": {
                "risk_score": 0,
                "risk_level": "UNKNOWN",
                "risk_reasons": ["Malformed or empty URL string"],
            },
        }

    components = extract_url_components(url_str)
    if not components.get("is_valid"):
        return {
            "url": url_str,
            "status": "error",
            "error": components.get("error", "Malformed URL structure"),
            "hostname": None,
            "registered_domain": None,
            "risk_score": 30,
            "risk_level": "MEDIUM",
            "indicators": ["Malformed URL syntax could not be safely parsed"],
            "components": components,
            "features": {},
            "external_reputation": {
                "provider": "VirusTotal",
                "is_malicious": None,
                "reputation_status": "not_analyzed",
            },
            "redirect_analysis": {"status": "not_analyzed"},
            "historical_correlation": {
                "history_status": "not_analyzed",
                "historical_match": None,
                "matching_case_ids": [],
                "match_count": 0,
            },
            "normalized_output": {
                "risk_score": 30,
                "risk_level": "MEDIUM",
                "risk_reasons": ["Malformed URL syntax could not be safely parsed"],
            },
        }

    # Non-web references such as mailto: are intentionally ignored.
    if components.get("is_non_web_reference") is True:
        return {
            "url": url_str,
            "status": "ignored",
            "error": None,
            "hostname": "",
            "registered_domain": None,
            "risk_score": 0,
            "risk_level": "LOW",
            "indicators": [],
            "components": {
                "scheme": components.get("scheme"),
                "port": None,
                "path": "",
                "query": "",
                "fragment": "",
            },
            "features": {
                "is_non_web_reference": True,
            },
            "external_reputation": {
                "provider": "VirusTotal",
                "is_malicious": None,
                "reputation_status": "skipped_non_web_reference",
            },
            "redirect_analysis": {"status": "skipped_non_web_reference"},
            "historical_correlation": {
                "history_status": "skipped_non_web_reference",
                "historical_match": None,
                "matching_case_ids": [],
                "match_count": 0,
            },
            "normalized_output": {
                "risk_score": 0,
                "risk_level": "LOW",
                "risk_reasons": [],
            },
        }

    features = extract_static_features(
        components,
        url_str,
        sender_root,
        original_url=original_url,
    )
    features["hostname"] = components.get("hostname")
    features["registered_domain"] = components.get("registered_domain")
    features["path"] = components.get("path") or ""
    features["query"] = components.get("query") or ""
    features["fragment"] = components.get("fragment") or ""

    reputation = (
        enrich_url_reputation(url_str)
        if enable_reputation
        else _disabled_reputation()
    )

    redirect_analysis = (
        analyze_redirect_chain(url_str)
        if enable_redirect_analysis
        else _disabled_redirect()
    )

    historical_correlation = correlate_url_with_previous_cases(
        url_str,
        previous_cases,
    )

    risk_assessment = calculate_url_risk(
        features,
        reputation,
        redirect_analysis,
        historical_correlation,
    )

    final_url = redirect_analysis.get("final_url")
    final_hostname = redirect_analysis.get("final_hostname")
    final_registered_domain = None
    if final_url and final_hostname:
        try:
            final_components = extract_url_components(final_url)
            final_registered_domain = final_components.get("registered_domain")
        except Exception:
            final_registered_domain = None

    redirect_output = dict(redirect_analysis)
    redirect_output["final_registered_domain"] = final_registered_domain

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
        "external_reputation": reputation,
        "redirect_analysis": redirect_output,
        "historical_correlation": historical_correlation,
        "normalized_output": {
            "risk_score": risk_assessment["risk_score"],
            "risk_level": risk_assessment["risk_level"],
            "risk_reasons": risk_assessment["indicators"],
        },
    }


# ============================================================
# MULTI URL ANALYSIS
# ============================================================


def analyze_urls(
    urls: Any,
    sender_email: Optional[str] = None,
    previous_cases: Optional[Iterable[Dict[str, Any]]] = None,
    enable_reputation: bool = True,
    enable_redirect_analysis: bool = True,
) -> Dict[str, Any]:
    if not isinstance(urls, (list, tuple, set)):
        urls = [urls] if urls else []

    unique_items: List[Any] = []
    seen = set()

    for item in urls:
        normalized = normalize_raw_url(item)
        key = normalized.lower() if normalized else str(item).strip().lower()
        if key in seen:
            continue
        seen.add(key)
        unique_items.append(item)

    sender_root = extract_sender_root_domain(sender_email)

    url_results: List[Dict[str, Any]] = []
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    unknown_count = 0
    max_score = 0

    for item in unique_items:
        analysis = analyze_single_url(
            item,
            sender_root=sender_root,
            previous_cases=previous_cases,
            enable_reputation=enable_reputation,
            enable_redirect_analysis=enable_redirect_analysis,
        )

        # Do not put mailto:/tel:/etc. in URL threat counts.
        if analysis.get("status") == "ignored":
            continue

        url_results.append(analysis)
        score = int(analysis.get("risk_score") or 0)
        max_score = max(max_score, score)
        level = analysis.get("risk_level", "UNKNOWN")

        if level == "CRITICAL":
            critical_count += 1
        elif level == "HIGH":
            high_count += 1
        elif level == "MEDIUM":
            medium_count += 1
        elif level == "LOW":
            low_count += 1
        else:
            unknown_count += 1

    if critical_count:
        overall_status = "CRITICAL"
    elif high_count:
        overall_status = "HIGH"
    elif medium_count:
        overall_status = "MEDIUM"
    elif low_count:
        overall_status = "LOW"
    else:
        overall_status = "UNKNOWN"

    return {
        "summary": {
            "total_urls": len(url_results),
            "critical_risk_urls": critical_count,
            "high_risk_urls": high_count,
            "medium_risk_urls": medium_count,
            "low_risk_urls": low_count,
            "unknown_risk_urls": unknown_count,
            "max_risk_score": max_score,
            "overall_status": overall_status,
        },
        "urls": url_results,
    }


# ============================================================
# CLI
# ============================================================


def _read_stdin_json() -> Dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Input JSON must be an object")
    return payload


def main() -> int:
    try:
        input_data = _read_stdin_json()

        result = analyze_urls(
            urls=input_data.get("urls", []),
            sender_email=input_data.get("sender_email"),
            previous_cases=input_data.get("previous_cases"),
            enable_reputation=bool(
                input_data.get("enable_reputation", True)
            ),
            enable_redirect_analysis=bool(
                input_data.get(
                    "enable_redirect_analysis",
                    ENABLE_REDIRECT_ANALYSIS,
                )
            ),
        )

        print(json.dumps(result, ensure_ascii=False), flush=True)
        return 0

    except json.JSONDecodeError as exc:
        print(
            json.dumps(
                {"error": f"Invalid JSON input: {exc}"},
                ensure_ascii=False,
            ),
            flush=True,
        )
        return 1
    except Exception as exc:
        print(
            json.dumps(
                {"error": str(exc)},
                ensure_ascii=False,
            ),
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
