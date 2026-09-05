from pprint import pprint
from intelligence.ip_intelligence import analyze_ip_intelligence
from intelligence.domain_intelligence import analyze_domain_intelligence

# Simulated exact document from your MongoDB Atlas instance
mongo_doc = {
    "headers": {
        "from": "Kajal <kajaltanu17.05@gmail.com>",
        "replyTo": None,
        "returnPath": None,
        "received": []
    },
    "links": [],
    "headerForensics": {
        "network_hops": {
            "origin_ip_candidate": None,
            "all_extracted_ips": []
        }
    }
}

def test_full_pipeline_on_mongo_doc():
    headers = mongo_doc.get("headers", {})
    hops_data = mongo_doc.get("headerForensics", {}).get("network_hops", {})

    # 1. Run IP Intelligence
    ip_results = analyze_ip_intelligence(
        origin_ip=hops_data.get("origin_ip_candidate"),
        all_extracted_ips=hops_data.get("all_extracted_ips", []),
        offline_mode=False
    )

    # 2. Run Domain Intelligence
    domain_results = analyze_domain_intelligence(
        from_header=headers.get("from"),
        reply_to_header=headers.get("replyTo"),
        return_path_header=headers.get("returnPath"),
        body_urls=mongo_doc.get("links", []),
        offline_mode=False
    )

    # 3. Payload ready for Threat Engine
    threat_engine_payload = {
        "ip_intelligence": ip_results,
        "domain_intelligence": domain_results,
        "extracted_signals": {
            **ip_results["signals"],
            **domain_results["signals"]
        }
    }

    pprint(threat_engine_payload)


def test_simulated_phishing_scenario():
    """Verify that simulated spoofing and mismatch signals trigger as expected."""
    simulated_phish_doc = {
        "headers": {
            "from": "Security Alert <support@paypa1-security.com>",
            "replyTo": "data-collector@random-inbox.net",
            "returnPath": "bounces@mailserver.net",
            "received": []
        },
        "links": [
            "https://login-verification-portal.biz/auth"
        ],
        "headerForensics": {
            "network_hops": {
                "origin_ip_candidate": "198.51.100.42",
                "all_extracted_ips": ["10.0.0.1", "198.51.100.42"]
            }
        }
    }

    hops_data = simulated_phish_doc["headerForensics"]["network_hops"]
    headers = simulated_phish_doc["headers"]

    ip_out = analyze_ip_intelligence(
        origin_ip=hops_data["origin_ip_candidate"],
        all_extracted_ips=hops_data["all_extracted_ips"],
        offline_mode=True
    )

    domain_out = analyze_domain_intelligence(
        from_header=headers["from"],
        reply_to_header=headers["replyTo"],
        return_path_header=headers["returnPath"],
        body_urls=simulated_phish_doc["links"],
        offline_mode=True
    )

    print("\n--- SIMULATED THREAT SIGNALS ---")
    signals = {**ip_out["signals"], **domain_out["signals"]}
    pprint(signals)

    # Assertions to confirm threat detection capabilities
    assert signals["reply_to_mismatch"] is True
    assert signals["return_path_mismatch"] is True
    assert signals["is_brand_lookalike"] is True
    assert signals["body_domain_mismatch"] is True



if __name__ == "__main__":
    print("=== TEST 1: REAL MONGO DOC ===")
    test_full_pipeline_on_mongo_doc()
    print("\n=== TEST 2: SIMULATED PHISHING DOC ===")
    test_simulated_phishing_scenario()