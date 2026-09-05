from typing import Any, Dict
from intelligence.ip_intelligence import analyze_ip_intelligence
from intelligence.domain_intelligence import analyze_domain_intelligence


def process_intelligence_pipeline(mongo_document: Dict[str, Any], offline_mode: bool = False) -> Dict[str, Any]:
    """
    Unified entry point for ThreadLens IP & Domain Intelligence modules.
    Accepts the MongoDB email forensic document and returns an enriched payload.
    """
    headers = mongo_document.get("headers", {})
    hops_data = mongo_document.get("headerForensics", {}).get("network_hops", {})
    links = mongo_document.get("links", [])

    ip_results = analyze_ip_intelligence(
        origin_ip=hops_data.get("origin_ip_candidate"),
        all_extracted_ips=hops_data.get("all_extracted_ips", []),
        offline_mode=offline_mode
    )

    domain_results = analyze_domain_intelligence(
        from_header=headers.get("from"),
        reply_to_header=headers.get("replyTo"),
        return_path_header=headers.get("returnPath"),
        body_urls=links,
        offline_mode=offline_mode
    )

    return {
        "ip_intelligence": ip_results,
        "domain_intelligence": domain_results,
        "intelligence_signals": {
            **ip_results["signals"],
            **domain_results["signals"]
        }
    }