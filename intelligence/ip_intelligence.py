"""
ThreadLens - IP Intelligence Module
Extracts, validates, classifies, and enriches email routing IPs.
"""

import ipaddress
from typing import Any, Dict, List, Optional
import requests


def is_valid_ip(ip_str: Optional[str]) -> bool:
    """Validate if a string is a valid IPv4 or IPv6 address."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def is_private_ip(ip_str: str) -> bool:
    """
    Check whether an IP belongs to private RFC 1918 / RFC 4193 ranges,
    loopback, or link-local.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        # Documentation IPs (198.51.100.0/24, 203.0.113.0/24, etc.) are used for testing
        # and should not be misclassified as internal LAN addresses.
        if ip_obj.is_loopback or ip_obj.is_link_local:
            return True
        
        # Explicit RFC 1918 (IPv4) & RFC 4193 (IPv6 ULA) checks
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return (
                ip_obj in ipaddress.ip_network("10.0.0.0/8")
                or ip_obj in ipaddress.ip_network("172.16.0.0/12")
                or ip_obj in ipaddress.ip_network("192.168.0.0/16")
            )
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return ip_obj in ipaddress.ip_network("fc00::/7")
            
        return False
    except ValueError:
        return False


def enrich_ip_metadata(ip_str: str, timeout_sec: float = 2.5) -> Dict[str, Any]:
    """
    Query ip-api.com for public IP metadata (ASN, ISP, approximate region).
    Fails safely without throwing exceptions on timeouts or network failures.
    """
    empty_enrichment = {
        "lookup_status": "skipped",
        "asn": None,
        "isp": None,
        "country": None,
        "region": None,
        "city": None,
        "is_hosting": False,
        "is_proxy": False,
    }

    if not is_valid_ip(ip_str) or is_private_ip(ip_str):
        empty_enrichment["lookup_status"] = "private_or_invalid"
        return empty_enrichment

    url = (
        f"http://ip-api.com/json/{ip_str.strip()}"
        "?fields=status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting"
    )

    try:
        response = requests.get(url, timeout=timeout_sec)
        if response.status_code != 200:
            empty_enrichment["lookup_status"] = f"http_{response.status_code}"
            return empty_enrichment

        data = response.json()
        if data.get("status") != "success":
            empty_enrichment["lookup_status"] = data.get("message", "api_failed")
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
        }
    except requests.RequestException:
        empty_enrichment["lookup_status"] = "network_timeout_or_error"
        return empty_enrichment


def analyze_ip_intelligence(
    origin_ip: Optional[str] = None,
    all_extracted_ips: Optional[List[str]] = None,
    offline_mode: bool = False
) -> Dict[str, Any]:
    """
    Main entry point for IP Intelligence. Consumes extracted IPs from header forensics
    or MongoDB document and outputs structured threat signals.
    """
    all_ips = all_extracted_ips or []
    
    # 1. Handle completely empty/missing IP data
    if not origin_ip and not all_ips:
        return {
            "status": "missing_ip_data",
            "routing_summary": {
                "total_extracted_ips": 0,
                "has_public_origin": False,
                "route_available": False,
            },
            "origin_ip_data": None,
            "all_hops": [],
            "signals": {
                "ip_origin_missing": True,
                "ip_origin_is_private_only": False,
                "ip_origin_is_hosting": False,
                "ip_origin_is_vpn_proxy": False,
            },
        }

    # 2. Pick candidate origin IP if none provided explicitly
    candidate_ip = origin_ip
    if not candidate_ip and all_ips:
        # Scan hops in reverse order for first valid IP
        for ip in reversed(all_ips):
            if is_valid_ip(ip):
                candidate_ip = ip
                break

    # 3. Analyze candidate IP
    is_private = is_private_ip(candidate_ip) if candidate_ip else False
    enrichment = {}
    if candidate_ip and not is_private and not offline_mode:
        enrichment = enrich_ip_metadata(candidate_ip)
    else:
        enrichment = {
            "lookup_status": "offline_or_private",
            "asn": None,
            "isp": None,
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "is_hosting": False,
            "is_proxy": False,
        }

    # 4. Hop breakdown
    parsed_hops = []
    for idx, ip in enumerate(all_ips):
        valid = is_valid_ip(ip)
        parsed_hops.append({
            "hop_index": idx,
            "ip": ip,
            "is_valid": valid,
            "is_private": is_private_ip(ip) if valid else False,
        })

    # 5. Export signals downstream
    return {
        "status": "success",
        "routing_summary": {
            "total_extracted_ips": len(all_ips),
            "has_public_origin": bool(candidate_ip and not is_private),
            "route_available": True,
        },
        "origin_ip_data": {
            "ip": candidate_ip,
            "is_private": is_private,
            **enrichment,
        },
        "all_hops": parsed_hops,
        "signals": {
            "ip_origin_missing": candidate_ip is None,
            "ip_origin_is_private_only": is_private,
            "ip_origin_is_hosting": enrichment.get("is_hosting", False),
            "ip_origin_is_vpn_proxy": enrichment.get("is_proxy", False),
        },
    }