"""
ThreadLens - IP Intelligence Module

Extracts, validates, classifies, and enriches email routing IPs.

Provides:
- IP validation
- Private/public classification
- IP metadata enrichment
- Backward-compatible boolean signals
- Normalized 0-100 risk scoring
- Safe UNKNOWN state when intelligence is unavailable
"""

import ipaddress
from typing import Any, Dict, List, Optional

import requests


# ============================================================
# IP VALIDATION
# ============================================================

def is_valid_ip(ip_str: Optional[str]) -> bool:
    """Return True when the supplied value is a valid IPv4/IPv6 address."""

    if not ip_str or not isinstance(ip_str, str):
        return False

    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


# ============================================================
# PRIVATE IP CHECK
# ============================================================

def is_private_ip(ip_str: Optional[str]) -> bool:
    """
    Check whether an IP is private/internal.

    Includes:
    - IPv4 RFC1918
    - IPv6 Unique Local Address
    - Loopback
    - Link-local
    """

    if not ip_str or not isinstance(ip_str, str):
        return False

    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())

        if ip_obj.is_loopback or ip_obj.is_link_local:
            return True

        if isinstance(ip_obj, ipaddress.IPv4Address):
            return (
                ip_obj in ipaddress.ip_network("10.0.0.0/8")
                or ip_obj in ipaddress.ip_network("172.16.0.0/12")
                or ip_obj in ipaddress.ip_network("192.168.0.0/16")
            )

        if isinstance(ip_obj, ipaddress.IPv6Address):
            return ip_obj in ipaddress.ip_network("fc00::/7")

        return False

    except ValueError:
        return False


# ============================================================
# IP METADATA ENRICHMENT
# ============================================================

def enrich_ip_metadata(
    ip_str: str,
    timeout_sec: float = 2.5
) -> Dict[str, Any]:
    """
    Query ip-api.com for public IP metadata.

    Important:
    ip-api.com gives network metadata such as hosting/proxy status,
    but it does NOT provide the malicious reputation, threat history,
    or origin anomaly signals required by the scoring model.

    Therefore those unavailable fields remain None.
    They are never assumed to be True or False.
    """

    empty_enrichment = {
        "lookup_status": "skipped",
        "asn": None,
        "isp": None,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "is_hosting": None,
        "is_proxy": None,
        "is_malicious": None,
        "has_threat_history": None,
        "has_origin_anomaly": None
    }

    if not is_valid_ip(ip_str):
        empty_enrichment["lookup_status"] = "invalid_ip"
        return empty_enrichment

    if is_private_ip(ip_str):
        empty_enrichment["lookup_status"] = "private_or_invalid"
        return empty_enrichment

    url = (
        f"http://ip-api.com/json/{ip_str.strip()}"
        "?fields="
        "status,message,country,countryCode,regionName,city,"
        "isp,org,as,proxy,hosting"
    )

    try:
        response = requests.get(
            url,
            timeout=timeout_sec
        )

        if response.status_code != 200:
            empty_enrichment["lookup_status"] = (
                f"http_{response.status_code}"
            )
            return empty_enrichment

        data = response.json()

        if not isinstance(data, dict):
            empty_enrichment["lookup_status"] = "invalid_api_response"
            return empty_enrichment

        if data.get("status") != "success":
            empty_enrichment["lookup_status"] = (
                data.get("message")
                or "api_failed"
            )
            return empty_enrichment

        return {
            "lookup_status": "success",
            "asn": data.get("as"),
            "isp": data.get("isp") or data.get("org"),
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "is_hosting": bool(data.get("hosting", False)),
            "is_proxy": bool(data.get("proxy", False)),

            # Not provided by ip-api.com.
            "is_malicious": None,
            "has_threat_history": None,
            "has_origin_anomaly": None
        }

    except requests.Timeout:
        empty_enrichment["lookup_status"] = "network_timeout_or_error"
        return empty_enrichment

    except requests.RequestException:
        empty_enrichment["lookup_status"] = "network_timeout_or_error"
        return empty_enrichment

    except ValueError:
        empty_enrichment["lookup_status"] = "invalid_api_response"
        return empty_enrichment


# ============================================================
# RISK LEVEL
# ============================================================

def get_ip_risk_level(
    score: int,
    known_signal: bool
) -> str:
    """
    Convert a normalized score into a risk level.

    0-39   LOW
    40-69  MEDIUM
    70-100 HIGH

    If no conclusive signal is available, return UNKNOWN.
    """

    if not known_signal:
        return "UNKNOWN"

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


# ============================================================
# IP RISK SCORING
# ============================================================

def calculate_ip_risk(
    ip_data: Optional[Dict[str, Any]],
    api_failed: bool = False
) -> Dict[str, Any]:
    """
    Calculate normalized IP risk score from 0-100.

    Scoring requested by the project:

        malicious        +50
        proxy/VPN/Tor    +25
        threat history   +15
        hosting           +10
        origin anomaly    +40

    Maximum score is capped at 100.

    Unknown/unavailable intelligence is never interpreted
    as malicious or clean.
    """

    if not ip_data:
        return {
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "risk_reasons": [
                "IP intelligence unavailable"
            ]
        }

    lookup_status = ip_data.get("lookup_status")

    unavailable_statuses = {
        "skipped",
        "network_timeout_or_error",
        "api_failed",
        "invalid_api_response",
        "offline_or_private",
        "http_403",
        "http_429",
        "http_500",
        "http_502",
        "http_503"
    }

    if api_failed or lookup_status in unavailable_statuses:
        return {
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "risk_reasons": [
                "IP intelligence API unavailable"
            ]
        }

    if lookup_status in {
        "private_or_invalid",
        "invalid_ip"
    }:
        return {
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "risk_reasons": [
                "IP is private or invalid"
            ]
        }

    score = 0
    reasons = []
    known_signal = False

    # --------------------------------------------------------
    # MALICIOUS REPUTATION +50
    # --------------------------------------------------------

    if ip_data.get("is_malicious") is True:
        score += 50
        known_signal = True

        reasons.append(
            "IP flagged as malicious by reputation intelligence"
        )

    # --------------------------------------------------------
    # PROXY / VPN / TOR +25
    # --------------------------------------------------------

    if ip_data.get("is_proxy") is True:
        score += 25
        known_signal = True

        reasons.append(
            "IP associated with proxy/VPN/Tor infrastructure"
        )

    # --------------------------------------------------------
    # THREAT HISTORY +15
    # --------------------------------------------------------

    if ip_data.get("has_threat_history") is True:
        score += 15
        known_signal = True

        reasons.append(
            "Historical threat activity associated with IP"
        )

    # --------------------------------------------------------
    # HOSTING +10
    # --------------------------------------------------------

    if ip_data.get("is_hosting") is True:
        score += 10
        known_signal = True

        reasons.append(
            "IP belongs to hosting/datacenter infrastructure"
        )

    # --------------------------------------------------------
    # ORIGIN ANOMALY +40
    # --------------------------------------------------------

    if ip_data.get("has_origin_anomaly") is True:
        score += 40
        known_signal = True

        reasons.append(
            "Routing or geographic origin anomaly detected"
        )

    # --------------------------------------------------------
    # CAP SCORE
    # --------------------------------------------------------

    final_score = min(
        max(score, 0),
        100
    )

    # --------------------------------------------------------
    # UNKNOWN WHEN NO CONCLUSIVE SIGNAL EXISTS
    # --------------------------------------------------------

    if not known_signal:
        return {
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "risk_reasons": [
                "No conclusive IP risk intelligence available"
            ]
        }

    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    risk_level = get_ip_risk_level(
        final_score,
        known_signal
    )

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "risk_reasons": reasons
    }


# ============================================================
# MAIN IP INTELLIGENCE
# ============================================================

def analyze_ip_intelligence(
    origin_ip: Optional[str] = None,
    all_extracted_ips: Optional[List[str]] = None,
    offline_mode: bool = False
) -> Dict[str, Any]:
    """
    Main IP Intelligence entry point.

    Existing output fields are preserved.

    New normalized fields:
        risk_score
        risk_level
        risk_reasons
        normalized_output
    """

    all_ips = (
        all_extracted_ips
        if isinstance(all_extracted_ips, list)
        else []
    )

    # ========================================================
    # EMPTY / MISSING IP DATA
    # ========================================================

    if not origin_ip and not all_ips:

        risk_assessment = {
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "risk_reasons": [
                "Missing IP data"
            ]
        }

        return {
            "status": "missing_ip_data",

            "routing_summary": {
                "total_extracted_ips": 0,
                "has_public_origin": False,
                "route_available": False
            },

            "origin_ip_data": None,

            "all_hops": [],

            # Existing boolean signals preserved.
            "signals": {
                "ip_origin_missing": True,
                "ip_origin_is_private_only": False,
                "ip_origin_is_hosting": False,
                "ip_origin_is_vpn_proxy": False
            },

            # New normalized output.
            "risk_score": risk_assessment["risk_score"],
            "risk_level": risk_assessment["risk_level"],
            "risk_reasons": risk_assessment["risk_reasons"],
            "normalized_output": risk_assessment
        }

    # ========================================================
    # SELECT CANDIDATE ORIGIN IP
    # ========================================================

    candidate_ip = origin_ip

    if not candidate_ip and all_ips:

        for ip in reversed(all_ips):

            if is_valid_ip(ip):

                candidate_ip = ip
                break

    # ========================================================
    # ANALYZE CANDIDATE IP
    # ========================================================

    is_private = (
        is_private_ip(candidate_ip)
        if candidate_ip
        else False
    )

    if (
        candidate_ip
        and not is_private
        and not offline_mode
    ):

        enrichment = enrich_ip_metadata(
            candidate_ip
        )

    else:

        enrichment = {
            "lookup_status": (
                "offline_or_private"
            ),
            "asn": None,
            "isp": None,
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "is_hosting": None,
            "is_proxy": None,
            "is_malicious": None,
            "has_threat_history": None,
            "has_origin_anomaly": None
        }

    # ========================================================
    # PARSE ALL HOPS
    # ========================================================

    parsed_hops = []

    for idx, ip in enumerate(all_ips):

        valid = is_valid_ip(ip)

        parsed_hops.append({
            "hop_index": idx,
            "ip": ip,
            "is_valid": valid,
            "is_private": (
                is_private_ip(ip)
                if valid
                else False
            )
        })

    # ========================================================
    # DETERMINE API FAILURE
    # ========================================================

    api_failed = (
        enrichment.get("lookup_status")
        not in {
            "success",
            "private_or_invalid",
            "invalid_ip",
            "offline_or_private"
        }
    )

    # ========================================================
    # CALCULATE NORMALIZED RISK
    # ========================================================

    risk_assessment = calculate_ip_risk(
        enrichment,
        api_failed=api_failed
    )

    # ========================================================
    # BACKWARD-COMPATIBLE BOOLEAN SIGNALS
    # ========================================================

    signals = {
        "ip_origin_missing":
            candidate_ip is None,

        "ip_origin_is_private_only":
            is_private,

        "ip_origin_is_hosting":
            enrichment.get("is_hosting") is True,

        "ip_origin_is_vpn_proxy":
            enrichment.get("is_proxy") is True
    }

    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {
        "status": "success",

        "routing_summary": {
            "total_extracted_ips": len(all_ips),
            "has_public_origin": bool(
                candidate_ip
                and not is_private
            ),
            "route_available": True
        },

        "origin_ip_data": {
            "ip": candidate_ip,
            "is_private": is_private,
            **enrichment
        },

        "all_hops": parsed_hops,

        # Existing signals preserved.
        "signals": signals,

        # New normalized fields.
        "risk_score":
            risk_assessment["risk_score"],

        "risk_level":
            risk_assessment["risk_level"],

        "risk_reasons":
            risk_assessment["risk_reasons"],

        # Grouped version for downstream modules.
        "normalized_output":
            risk_assessment
    }