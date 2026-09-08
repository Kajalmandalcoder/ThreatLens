"""
ThreadLens - IP Intelligence Module

Features:
- IPv4 / IPv6 validation
- Public / private classification
- IP version detection
- Geolocation
- ISP / organization
- ASN
- Hosting / datacenter detection
- Proxy detection
- Tor detection
- AbuseIPDB reputation
- Abuse confidence score
- Abuse report history
- Origin anomaly support
- Historical case correlation support
- IP <-> Domain correlation support
- IP <-> Campaign correlation support
- Backward-compatible boolean signals
- Normalized 0-100 risk scoring
- Safe UNKNOWN state when intelligence is unavailable

IP scoring:
    malicious        +50
    proxy/VPN/Tor    +25
    threat history   +15
    hosting          +10
    origin anomaly   +40

Final score is capped at 100.

Important:
Unknown intelligence is NEVER treated as clean or malicious.
"""

import ipaddress
import os
from typing import Any, Dict, List, Optional, Iterable, Set

import requests


# ============================================================
# ENVIRONMENT
# ============================================================

try:
    from dotenv import load_dotenv

    PROJECT_ROOT = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            ".."
        )
    )

    BACKEND_ENV = os.path.join(
        PROJECT_ROOT,
        "backend",
        ".env"
    )

    if os.path.exists(BACKEND_ENV):
        load_dotenv(
            BACKEND_ENV,
            override=True
        )

except Exception:
    pass


# ============================================================
# CONFIGURATION
# ============================================================

ABUSEIPDB_API_KEY = os.getenv(
    "ABUSEIPDB_API_KEY"
)

ABUSEIPDB_URL = (
    "https://api.abuseipdb.com/api/v2/check"
)

ABUSEIPDB_MAX_AGE_DAYS = int(
    os.getenv(
        "ABUSEIPDB_MAX_AGE_DAYS",
        "90"
    )
)

ABUSEIPDB_MALICIOUS_THRESHOLD = int(
    os.getenv(
        "ABUSEIPDB_MALICIOUS_THRESHOLD",
        "80"
    )
)


# ============================================================
# IP VALIDATION
# ============================================================

def is_valid_ip(
    ip_str: Optional[str]
) -> bool:
    """Return True if value is a valid IPv4 or IPv6 address."""

    if not ip_str or not isinstance(
        ip_str,
        str
    ):
        return False

    try:
        ipaddress.ip_address(
            ip_str.strip()
        )
        return True

    except ValueError:
        return False


# ============================================================
# IP VERSION
# ============================================================

def get_ip_version(
    ip_str: Optional[str]
) -> Optional[int]:
    """Return 4 for IPv4, 6 for IPv6, otherwise None."""

    if not is_valid_ip(ip_str):
        return None

    try:
        return ipaddress.ip_address(
            ip_str.strip()
        ).version

    except ValueError:
        return None


# ============================================================
# PRIVATE IP
# ============================================================

def is_private_ip(
    ip_str: Optional[str]
) -> bool:
    """
    Return True for:
    - IPv4 RFC1918
    - IPv6 ULA
    - loopback
    - link-local
    """

    if not ip_str or not isinstance(
        ip_str,
        str
    ):
        return False

    try:
        ip_obj = ipaddress.ip_address(
            ip_str.strip()
        )

        if (
            ip_obj.is_loopback
            or ip_obj.is_link_local
        ):
            return True

        if isinstance(
            ip_obj,
            ipaddress.IPv4Address
        ):
            return (
                ip_obj in ipaddress.ip_network(
                    "10.0.0.0/8"
                )
                or ip_obj in ipaddress.ip_network(
                    "172.16.0.0/12"
                )
                or ip_obj in ipaddress.ip_network(
                    "192.168.0.0/16"
                )
            )

        if isinstance(
            ip_obj,
            ipaddress.IPv6Address
        ):
            return ip_obj in ipaddress.ip_network(
                "fc00::/7"
            )

        return False

    except ValueError:
        return False


# ============================================================
# IP-API NETWORK METADATA
# ============================================================

def enrich_ip_metadata(
    ip_str: str,
    timeout_sec: float = 2.5
) -> Dict[str, Any]:
    """
    Enrich a public IP with network metadata using ip-api.com.

    Unknown values remain None.
    """

    empty = {
        "lookup_status": "skipped",
        "asn": None,
        "isp": None,
        "organization": None,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "is_hosting": None,
        "is_proxy": None
    }

    if not is_valid_ip(ip_str):
        empty["lookup_status"] = "invalid_ip"
        return empty

    if is_private_ip(ip_str):
        empty["lookup_status"] = (
            "private_or_invalid"
        )
        return empty

    url = (
        f"http://ip-api.com/json/"
        f"{ip_str.strip()}"
        "?fields="
        "status,message,country,countryCode,"
        "regionName,city,isp,org,as,proxy,hosting"
    )

    try:
        response = requests.get(
            url,
            timeout=timeout_sec
        )

        if response.status_code != 200:
            empty["lookup_status"] = (
                f"http_{response.status_code}"
            )
            return empty

        data = response.json()

        if not isinstance(
            data,
            dict
        ):
            empty["lookup_status"] = (
                "invalid_api_response"
            )
            return empty

        if data.get("status") != "success":
            empty["lookup_status"] = (
                data.get("message")
                or "api_failed"
            )
            return empty

        return {
            "lookup_status": "success",
            "asn": data.get("as"),
            "isp": (
                data.get("isp")
                or data.get("org")
            ),
            "organization": data.get("org"),
            "country": data.get("country"),
            "country_code": data.get(
                "countryCode"
            ),
            "region": data.get(
                "regionName"
            ),
            "city": data.get("city"),
            "is_hosting": bool(
                data.get(
                    "hosting",
                    False
                )
            ),
            "is_proxy": bool(
                data.get(
                    "proxy",
                    False
                )
            )
        }

    except requests.Timeout:
        empty["lookup_status"] = (
            "network_timeout_or_error"
        )
        return empty

    except requests.RequestException:
        empty["lookup_status"] = (
            "network_timeout_or_error"
        )
        return empty

    except ValueError:
        empty["lookup_status"] = (
            "invalid_api_response"
        )
        return empty


# ============================================================
# ABUSEIPDB REPUTATION
# ============================================================

def enrich_ip_reputation(
    ip_str: str,
    timeout_sec: float = 3.0
) -> Dict[str, Any]:
    """
    Check IP reputation using AbuseIPDB API v2.

    Uses:
    - abuseConfidenceScore
    - totalReports
    - lastReportedAt
    - usageType
    - isTor
    - isWhitelisted
    - domain
    - hostnames

    Returns UNKNOWN/unavailable values safely.
    """

    empty = {
        "reputation_status":
            "unavailable",

        "provider":
            "AbuseIPDB",

        "abuse_confidence_score":
            None,

        "total_reports":
            None,

        "last_reported_at":
            None,

        "is_malicious":
            None,

        "has_threat_history":
            None,

        "is_tor":
            None,

        "usage_type":
            None,

        "domain_name":
            None,

        "hostnames":
            [],

        "is_whitelisted":
            None
    }

    if not is_valid_ip(ip_str):
        empty["reputation_status"] = (
            "invalid_ip"
        )
        return empty

    if is_private_ip(ip_str):
        empty["reputation_status"] = (
            "private_ip"
        )
        return empty

    if not ABUSEIPDB_API_KEY:
        empty["reputation_status"] = (
            "api_key_missing"
        )
        return empty

    params = {
        "ipAddress":
            ip_str.strip(),

        "maxAgeInDays":
            min(
                max(
                    ABUSEIPDB_MAX_AGE_DAYS,
                    1
                ),
                365
            )
    }

    headers = {
        "Accept":
            "application/json",

        "Key":
            ABUSEIPDB_API_KEY
    }

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=timeout_sec
        )

        if response.status_code != 200:

            empty["reputation_status"] = (
                f"http_{response.status_code}"
            )

            return empty

        payload = response.json()

        if not isinstance(
            payload,
            dict
        ):
            empty["reputation_status"] = (
                "invalid_api_response"
            )
            return empty

        data = payload.get(
            "data"
        )

        if not isinstance(
            data,
            dict
        ):
            empty["reputation_status"] = (
                "missing_data"
            )
            return empty

        abuse_score = data.get(
            "abuseConfidenceScore"
        )

        total_reports = data.get(
            "totalReports"
        )

        is_tor = data.get(
            "isTor"
        )

        is_whitelisted = data.get(
            "isWhitelisted"
        )

        # Abuse score is authoritative only when numeric.
        is_malicious = (
            abuse_score >=
            ABUSEIPDB_MALICIOUS_THRESHOLD
            if isinstance(
                abuse_score,
                (int, float)
            )
            else None
        )

        # Threat history is based on reports returned
        # within maxAgeInDays.
        has_threat_history = (
            total_reports > 0
            if isinstance(
                total_reports,
                (int, float)
            )
            else None
        )

        return {
            "reputation_status":
                "success",

            "provider":
                "AbuseIPDB",

            "abuse_confidence_score":
                abuse_score,

            "total_reports":
                total_reports,

            "last_reported_at":
                data.get(
                    "lastReportedAt"
                ),

            "is_malicious":
                is_malicious,

            "has_threat_history":
                has_threat_history,

            "is_tor":
                (
                    bool(is_tor)
                    if isinstance(
                        is_tor,
                        bool
                    )
                    else None
                ),

            "usage_type":
                data.get(
                    "usageType"
                ),

            "domain_name":
                data.get(
                    "domain"
                ),

            "hostnames":
                (
                    data.get(
                        "hostnames"
                    )
                    if isinstance(
                        data.get(
                            "hostnames"
                        ),
                        list
                    )
                    else []
                ),

            "is_whitelisted":
                is_whitelisted
        }

    except requests.Timeout:
        empty["reputation_status"] = (
            "network_timeout_or_error"
        )
        return empty

    except requests.RequestException:
        empty["reputation_status"] = (
            "network_timeout_or_error"
        )
        return empty

    except ValueError:
        empty["reputation_status"] = (
            "invalid_api_response"
        )
        return empty


# ============================================================
# VPN / PROXY / TOR
# ============================================================

def determine_proxy_vpn_tor(
    network_data: Dict[str, Any],
    reputation_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Combine available proxy/Tor intelligence.

    Important:
    - is_proxy comes from ip-api.
    - is_tor comes from AbuseIPDB.
    - VPN-specific intelligence is NOT invented.
    """

    proxy = network_data.get(
        "is_proxy"
    )

    tor = reputation_data.get(
        "is_tor"
    )

    proxy_known = isinstance(
        proxy,
        bool
    )

    tor_known = isinstance(
        tor,
        bool
    )

    is_proxy_vpn_tor = None

    if (
        proxy_known
        or tor_known
    ):
        is_proxy_vpn_tor = (
            proxy is True
            or tor is True
        )

    return {
        "is_proxy": proxy,
        "is_tor": tor,
        "is_vpn": None,
        "is_proxy_vpn_tor":
            is_proxy_vpn_tor
    }


# ============================================================
# ORIGIN ANOMALY
# ============================================================

def detect_origin_anomaly(
    candidate_ip: Optional[str],
    candidate_data: Dict[str, Any],
    previous_hop_data: Optional[Iterable[Dict[str, Any]]] = None,
    expected_country: Optional[str] = None
) -> Dict[str, Any]:
    """
    Detect origin anomalies only when there is enough evidence.

    Current supported checks:

    1. Expected-country mismatch:
       If expected_country is explicitly supplied and the
       candidate IP country differs.

    2. Route geography mismatch:
       If previous hop metadata contains countries and the
       candidate country is available.

    Otherwise anomaly remains UNKNOWN.

    We deliberately do NOT label a Google/Microsoft/datacenter
    IP as anomalous simply because it is hosting.
    """

    result = {
        "has_origin_anomaly":
            None,

        "origin_anomaly_reason":
            None
    }

    if not candidate_ip:
        return result

    candidate_country = candidate_data.get(
        "country"
    )

    # Explicit expected country.
    if (
        expected_country
        and candidate_country
    ):

        if (
            candidate_country.strip().lower()
            != expected_country.strip().lower()
        ):
            return {
                "has_origin_anomaly":
                    True,

                "origin_anomaly_reason":
                    (
                        "Origin country differs from "
                        "expected country"
                    )
            }

        return {
            "has_origin_anomaly":
                False,

            "origin_anomaly_reason":
                "Origin country matches expected country"
        }

    # Optional previous hop metadata.
    if previous_hop_data is not None:
        countries = []

        for hop in previous_hop_data:

            if not isinstance(
                hop,
                dict
            ):
                continue

            country = hop.get(
                "country"
            )

            if country:
                countries.append(
                    str(country).strip().lower()
                )

        if (
            candidate_country
            and countries
        ):

            # We do not claim a geographic anomaly simply because
            # countries change during normal email routing.
            # This remains UNKNOWN unless an explicit anomaly rule
            # is introduced.
            result[
                "origin_anomaly_reason"
            ] = (
                "Route geography available; "
                "no abnormality rule triggered"
            )

            result[
                "has_origin_anomaly"
            ] = False

    return result


# ============================================================
# RISK LEVEL
# ============================================================

def get_ip_risk_level(
    score: int,
    known_signal: bool
) -> str:

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
    ip_data: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Calculate normalized 0-100 IP risk score.

    Weights:
        malicious        +50
        proxy/VPN/Tor    +25
        threat history   +15
        hosting           +10
        origin anomaly    +40
    """

    if not ip_data:
        return {
            "risk_score":
                0,

            "risk_level":
                "UNKNOWN",

            "risk_reasons": [
                "IP intelligence unavailable"
            ]
        }

    if ip_data.get(
        "lookup_status"
    ) in {
        "network_timeout_or_error",
        "api_failed",
        "invalid_api_response",
        "http_401",
        "http_403",
        "http_429",
        "http_500",
        "http_502",
        "http_503"
    }:
        return {
            "risk_score":
                0,

            "risk_level":
                "UNKNOWN",

            "risk_reasons": [
                "IP network intelligence unavailable"
            ]
        }

    score = 0
    reasons = []

    known_signal = False

    # --------------------------------------------------------
    # MALICIOUS +50
    # --------------------------------------------------------

    if (
        ip_data.get(
            "is_malicious"
        )
        is True
    ):
        score += 50
        known_signal = True

        reasons.append(
            "IP has high malicious reputation confidence"
        )

    # --------------------------------------------------------
    # PROXY / VPN / TOR +25
    # --------------------------------------------------------

    proxy_vpn_tor = ip_data.get(
        "is_proxy_vpn_tor"
    )

    if proxy_vpn_tor is True:
        score += 25
        known_signal = True

        reasons.append(
            "IP is associated with proxy/VPN/Tor infrastructure"
        )

    # --------------------------------------------------------
    # THREAT HISTORY +15
    # --------------------------------------------------------

    if (
        ip_data.get(
            "has_threat_history"
        )
        is True
    ):
        score += 15
        known_signal = True

        reasons.append(
            "IP has previous abuse reports"
        )

    # --------------------------------------------------------
    # HOSTING +10
    # --------------------------------------------------------

    if (
        ip_data.get(
            "is_hosting"
        )
        is True
    ):
        score += 10
        known_signal = True

        reasons.append(
            "IP belongs to hosting/datacenter infrastructure"
        )

    # --------------------------------------------------------
    # ORIGIN ANOMALY +40
    # --------------------------------------------------------

    if (
        ip_data.get(
            "has_origin_anomaly"
        )
        is True
    ):
        score += 40
        known_signal = True

        reasons.append(
            ip_data.get(
                "origin_anomaly_reason"
            )
            or "Origin anomaly detected"
        )

    # --------------------------------------------------------
    # CAP
    # --------------------------------------------------------

    score = min(
        max(score, 0),
        100
    )

    # --------------------------------------------------------
    # UNKNOWN
    # --------------------------------------------------------

    if not known_signal:

        network_known = (
            ip_data.get(
                "lookup_status"
            ) == "success"
        )

        reputation_known = (
            ip_data.get(
                "reputation_status"
            ) == "success"
        )

        if (
            network_known
            or reputation_known
        ):
            return {
                "risk_score":
                    0,

                "risk_level":
                    "LOW",

                "risk_reasons": [
                    "No known IP risk indicators detected"
                ]
            }

        return {
            "risk_score":
                0,

            "risk_level":
                "UNKNOWN",

            "risk_reasons": [
                "No conclusive IP risk intelligence available"
            ]
        }

    return {
        "risk_score":
            score,

        "risk_level":
            get_ip_risk_level(
                score,
                known_signal
            ),

        "risk_reasons":
            reasons
    }


# ============================================================
# HISTORICAL IP CASE CORRELATION
# ============================================================

def correlate_ip_with_previous_cases(
    origin_ip: Optional[str],
    previous_cases: Optional[Iterable[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Correlate an IP against already-fetched previous cases.

    This function does NOT connect directly to MongoDB.
    The caller/controller can pass matching case documents.

    This keeps the intelligence module independent and prevents
    MongoDB schema assumptions from breaking it.
    """

    if not origin_ip:
        return {
            "history_status":
                "unavailable",

            "historical_match":
                None,

            "matching_case_ids":
                [],

            "match_count":
                0
        }

    if previous_cases is None:
        return {
            "history_status":
                "not_provided",

            "historical_match":
                None,

            "matching_case_ids":
                [],

            "match_count":
                0
        }

    matches = []

    target_ip = origin_ip.strip()

    for case in previous_cases:

        if not isinstance(
            case,
            dict
        ):
            continue

        case_id = (
            case.get(
                "caseId"
            )
            or case.get(
                "_id"
            )
        )

        candidate_ips: Set[str] = set()

        # Common possible locations.
        ip_intel = case.get(
            "ipIntelligence"
        )

        if isinstance(
            ip_intel,
            dict
        ):

            origin_data = ip_intel.get(
                "origin_ip_data"
            )

            if isinstance(
                origin_data,
                dict
            ):
                old_ip = origin_data.get(
                    "ip"
                )

                if old_ip:
                    candidate_ips.add(
                        str(old_ip).strip()
                    )

            all_hops = ip_intel.get(
                "all_hops"
            )

            if isinstance(
                all_hops,
                list
            ):

                for hop in all_hops:

                    if not isinstance(
                        hop,
                        dict
                    ):
                        continue

                    old_ip = hop.get(
                        "ip"
                    )

                    if old_ip:
                        candidate_ips.add(
                            str(old_ip).strip()
                        )

        # Top-level fallback.
        top_ip = case.get(
            "origin_ip"
        )

        if top_ip:
            candidate_ips.add(
                str(top_ip).strip()
            )

        if target_ip in candidate_ips:

            if case_id is not None:
                matches.append(
                    str(case_id)
                )

    return {
        "history_status":
            "success",

        "historical_match":
            bool(matches),

        "matching_case_ids":
            matches,

        "match_count":
            len(matches)
    }


# ============================================================
# IP <-> DOMAIN CORRELATION
# ============================================================

def correlate_ip_with_domains(
    origin_ip: Optional[str],
    observed_domains: Optional[Iterable[str]] = None,
    ip_domain_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create an explicit IP-domain correlation result.

    This is based only on supplied intelligence; it does not
    invent passive-DNS relationships.
    """

    if not origin_ip:
        return {
            "status":
                "unavailable",

            "correlated_domains":
                [],

            "correlation_count":
                0
        }

    domains = set()

    if observed_domains:
        for domain in observed_domains:
            if domain:
                domains.add(
                    str(domain).strip().lower()
                )

    if ip_domain_name:
        domains.add(
            str(
                ip_domain_name
            ).strip().lower()
        )

    return {
        "status":
            "success",

        "correlated_domains":
            sorted(domains),

        "correlation_count":
            len(domains)
    }


# ============================================================
# IP <-> CAMPAIGN CORRELATION
# ============================================================
def correlate_ip_with_campaigns(
    origin_ip: Optional[str],
    previous_cases: Optional[Iterable[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Find campaign IDs from previous cases that contain the same IP.

    This function only reports campaign IDs already stored in previous
    cases. It does not invent or assign a new campaign.
    """

    if not origin_ip:
        return {
            "status": "unavailable",
            "campaign_match": None,
            "campaign_ids": []
        }

    if previous_cases is None:
        return {
            "status": "not_provided",
            "campaign_match": None,
            "campaign_ids": []
        }

    # Convert iterable to a list so it can be safely iterated multiple times.
    cases = list(previous_cases)

    history = correlate_ip_with_previous_cases(
        origin_ip,
        cases
    )

    matching_case_ids = set(
        history.get(
            "matching_case_ids",
            []
        )
    )

    campaign_ids = set()

    for case in cases:
        if not isinstance(
            case,
            dict
        ):
            continue

        case_id = case.get(
            "caseId"
        )

        if case_id is None:
            continue

        case_id = str(case_id)

        if case_id not in matching_case_ids:
            continue

        campaign_id = (
            case.get("campaignId")
            or case.get("campaign_id")
        )

        if campaign_id:
            campaign_ids.add(
                str(campaign_id)
            )

    campaign_ids = sorted(
        campaign_ids
    )

    return {
        "status": "success",
        "campaign_match": bool(
            campaign_ids
        ),
        "campaign_ids": campaign_ids
    }


# ============================================================
# MAIN IP INTELLIGENCE
# ============================================================

def analyze_ip_intelligence(
    origin_ip: Optional[str] = None,
    all_extracted_ips: Optional[List[str]] = None,
    offline_mode: bool = False,
    previous_hop_data: Optional[Iterable[Dict[str, Any]]] = None,
    expected_country: Optional[str] = None,
    previous_cases: Optional[Iterable[Dict[str, Any]]] = None,
    observed_domains: Optional[Iterable[str]] = None
) -> Dict[str, Any]:
    """
    Main IP Intelligence entry point.

    Existing parameters remain backward compatible.

    Optional new parameters:
        previous_hop_data
        expected_country
        previous_cases
        observed_domains

    These allow higher-level orchestration to provide
    correlation/anomaly data without coupling this module
    directly to MongoDB.
    """

    all_ips = (
        all_extracted_ips
        if isinstance(
            all_extracted_ips,
            list
        )
        else []
    )

    # ========================================================
    # EMPTY DATA
    # ========================================================

    if (
        not origin_ip
        and not all_ips
    ):

        risk_assessment = {
            "risk_score":
                0,

            "risk_level":
                "UNKNOWN",

            "risk_reasons": [
                "Missing IP data"
            ]
        }

        return {
            "status":
                "missing_ip_data",

            "routing_summary": {
                "total_extracted_ips":
                    0,

                "has_public_origin":
                    False,

                "route_available":
                    False
            },

            "origin_ip_data":
                None,

            "all_hops":
                [],

            "signals": {
                "ip_origin_missing":
                    True,

                "ip_origin_is_private_only":
                    False,

                "ip_origin_is_hosting":
                    False,

                "ip_origin_is_vpn_proxy":
                    None,

                "ip_origin_is_malicious":
                    None,

                "ip_origin_has_threat_history":
                    None
            },

            "risk_score":
                0,

            "risk_level":
                "UNKNOWN",

            "risk_reasons":
                [
                    "Missing IP data"
                ],

            "normalized_output":
                risk_assessment,

            "historical_correlation":
                correlate_ip_with_previous_cases(
                    None,
                    previous_cases
                ),

            "ip_domain_correlation":
                correlate_ip_with_domains(
                    None,
                    observed_domains
                ),

            "ip_campaign_correlation":
                correlate_ip_with_campaigns(
                    None,
                    previous_cases
                )
        }

    # ========================================================
    # SELECT ORIGIN CANDIDATE
    # ========================================================

    candidate_ip = origin_ip

    if not candidate_ip and all_ips:

        for ip in reversed(
            all_ips
        ):

            if is_valid_ip(ip):

                candidate_ip = ip
                break

    # ========================================================
    # ORIGIN IP STATE
    # ========================================================

    ip_version = get_ip_version(
        candidate_ip
    )

    is_private = (
        is_private_ip(
            candidate_ip
        )
        if candidate_ip
        else False
    )

    # ========================================================
    # NETWORK METADATA
    # ========================================================

    if (
        candidate_ip
        and not is_private
        and not offline_mode
    ):

        network_data = enrich_ip_metadata(
            candidate_ip
        )

    else:

        network_data = {
            "lookup_status":
                "offline_or_private",

            "asn":
                None,

            "isp":
                None,

            "organization":
                None,

            "country":
                None,

            "country_code":
                None,

            "region":
                None,

            "city":
                None,

            "is_hosting":
                None,

            "is_proxy":
                None
        }

    # ========================================================
    # REPUTATION
    # ========================================================

    if (
        candidate_ip
        and not is_private
        and not offline_mode
    ):

        reputation_data = enrich_ip_reputation(
            candidate_ip
        )

    else:

        reputation_data = {
            "reputation_status":
                "offline_or_private",

            "provider":
                "AbuseIPDB",

            "abuse_confidence_score":
                None,

            "total_reports":
                None,

            "last_reported_at":
                None,

            "is_malicious":
                None,

            "has_threat_history":
                None,

            "is_tor":
                None,

            "usage_type":
                None,

            "domain_name":
                None,

            "hostnames":
                [],

            "is_whitelisted":
                None
        }

    # ========================================================
    # PROXY / VPN / TOR
    # ========================================================

    proxy_vpn_tor = determine_proxy_vpn_tor(
        network_data,
        reputation_data
    )

    # ========================================================
    # ORIGIN ANOMALY
    # ========================================================

    anomaly_data = detect_origin_anomaly(
        candidate_ip,
        {
            **network_data,
            **reputation_data
        },
        previous_hop_data=previous_hop_data,
        expected_country=expected_country
    )

    # ========================================================
    # SCORING DATA
    # ========================================================

    scoring_data = {

        **network_data,

        **reputation_data,

        "is_proxy_vpn_tor":
            proxy_vpn_tor[
                "is_proxy_vpn_tor"
            ],

        "has_origin_anomaly":
            anomaly_data[
                "has_origin_anomaly"
            ],

        "origin_anomaly_reason":
            anomaly_data[
                "origin_anomaly_reason"
            ]
    }

    # ========================================================
    # ALL HOPS
    # ========================================================

    parsed_hops = []

    for idx, ip in enumerate(
        all_ips
    ):

        valid = is_valid_ip(
            ip
        )

        parsed_hops.append({

            "hop_index":
                idx,

            "ip":
                ip,

            "ip_version":
                get_ip_version(
                    ip
                ),

            "is_valid":
                valid,

            "is_private":
                (
                    is_private_ip(ip)
                    if valid
                    else False
                )
        })

    # ========================================================
    # API STATES
    # ========================================================

    network_known = (
        network_data.get(
            "lookup_status"
        )
        == "success"
    )

    reputation_known = (
        reputation_data.get(
            "reputation_status"
        )
        == "success"
    )

    # ========================================================
    # RISK
    # ========================================================

    risk_assessment = calculate_ip_risk(
        scoring_data
    )

    # ========================================================
    # HISTORICAL CORRELATION
    # ========================================================

    historical_correlation = (
        correlate_ip_with_previous_cases(
            candidate_ip,
            previous_cases
        )
    )

    # ========================================================
    # DOMAIN CORRELATION
    # ========================================================

    ip_domain_correlation = (
        correlate_ip_with_domains(
            candidate_ip,
            observed_domains,  
        )
    )

    # ========================================================
    # CAMPAIGN CORRELATION
    # ========================================================

    ip_campaign_correlation = (
        correlate_ip_with_campaigns(
            candidate_ip,
            previous_cases
        )
    )

    # ========================================================
    # BACKWARD COMPATIBLE SIGNALS
    # ========================================================

    signals = {

        "ip_origin_missing":
            candidate_ip is None,

        "ip_origin_is_private_only":
            is_private,

        "ip_origin_is_hosting":
            network_data.get(
                "is_hosting"
            ) is True,

        "ip_origin_is_vpn_proxy":
            proxy_vpn_tor.get(
                "is_proxy_vpn_tor"
            ),

        "ip_origin_is_malicious":
            reputation_data.get(
                "is_malicious"
            ),

        "ip_origin_has_threat_history":
            reputation_data.get(
                "has_threat_history"
            ),

        "ip_origin_is_tor":
            reputation_data.get(
                "is_tor"
            ),

        "ip_origin_has_anomaly":
            anomaly_data.get(
                "has_origin_anomaly"
            )
    }

    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {

        "status":
            "success",

        "routing_summary": {

            "total_extracted_ips":
                len(all_ips),

            "has_public_origin":
                bool(
                    candidate_ip
                    and not is_private
                ),

            "route_available":
                True
        },

        # ====================================================
        # ORIGIN IP DATA
        # ====================================================

        "origin_ip_data": {

            "ip":
                candidate_ip,

            "ip_version":
                ip_version,

            "is_private":
                is_private,

            **network_data,

            **reputation_data,

            "is_vpn":
                proxy_vpn_tor[
                    "is_vpn"
                ],

            "is_proxy_vpn_tor":
                proxy_vpn_tor[
                    "is_proxy_vpn_tor"
                ],

            "has_origin_anomaly":
                anomaly_data[
                    "has_origin_anomaly"
                ],

            "origin_anomaly_reason":
                anomaly_data[
                    "origin_anomaly_reason"
                ]
        },

        # ====================================================
        # HOPS
        # ====================================================

        "all_hops":
            parsed_hops,

        # ====================================================
        # LEGACY SIGNALS
        # ====================================================

        "signals":
            signals,

        # ====================================================
        # NORMALIZED RISK
        # ====================================================

        "risk_score":
            risk_assessment[
                "risk_score"
            ],

        "risk_level":
            risk_assessment[
                "risk_level"
            ],

        "risk_reasons":
            risk_assessment[
                "risk_reasons"
            ],

        "normalized_output":
            risk_assessment,

        # ====================================================
        # CORRELATION
        # ====================================================

        "historical_correlation":
            historical_correlation,

        "ip_domain_correlation":
            ip_domain_correlation,

        "ip_campaign_correlation":
            ip_campaign_correlation,

        # ====================================================
        # INTELLIGENCE AVAILABILITY
        # ====================================================

        "intelligence_availability": {

            "network_metadata":
                network_known,

            "reputation":
                reputation_known,

            "vpn":
                proxy_vpn_tor[
                    "is_vpn"
                ]
                is not None,

            "proxy":
                network_data.get(
                    "is_proxy"
                )
                is not None,

            "tor":
                reputation_data.get(
                    "is_tor"
                )
                is not None,

            "origin_anomaly":
                anomaly_data.get(
                    "has_origin_anomaly"
                )
                is not None
        }
    }