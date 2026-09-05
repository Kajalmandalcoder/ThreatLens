from intelligence.ip_intelligence import analyze_ip_intelligence, is_private_ip, is_valid_ip


def test_validation_and_private_filtering():
    assert is_valid_ip("192.168.1.1") is True
    assert is_valid_ip("not_an_ip") is False
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("192.168.0.5") is True
    assert is_private_ip("8.8.8.8") is False


def test_empty_mongodb_document_case():
    """Matches the exact MongoDB sample where hops and origin are empty/null."""
    result = analyze_ip_intelligence(origin_ip=None, all_extracted_ips=[])
    assert result["status"] == "missing_ip_data"
    assert result["signals"]["ip_origin_missing"] is True
    assert result["routing_summary"]["route_available"] is False


def test_public_ip_offline_and_signals():
    """Verify clean signal output without throwing errors."""
    sample_hops = ["10.0.0.1", "198.51.100.24"]
    result = analyze_ip_intelligence(
        origin_ip="198.51.100.24",
        all_extracted_ips=sample_hops,
        offline_mode=True,
    )
    assert result["status"] == "success"
    assert result["origin_ip_data"]["ip"] == "198.51.100.24"
    assert result["signals"]["ip_origin_missing"] is False
    assert result["signals"]["ip_origin_is_private_only"] is False