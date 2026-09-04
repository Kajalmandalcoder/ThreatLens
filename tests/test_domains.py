from intelligence.domain_intelligence import (
    analyze_domain_intelligence,
    detect_lookalike_brand,
    extract_domain_parts,
)


def test_domain_extraction():
    parts = extract_domain_parts("Kajal <kajaltanu17.05@gmail.com>")
    assert parts["registered_domain"] == "gmail.com"
    assert parts["domain_name"] == "gmail"
    assert parts["suffix"] == "com"


def test_lookalike_detection():
    brands = ["paypal", "google"]
    
    # Exact brand is NOT a lookalike
    assert detect_lookalike_brand("google", brands)["is_lookalike"] is False

    # Typosquatting / lookalike variant
    result = detect_lookalike_brand("paypa1", brands)
    assert result["is_lookalike"] is True
    assert result["matched_brand"] == "paypal"


def test_header_mismatch_and_null_safety():
    """Verify safety with missing reply-to and mismatch detection."""
    result = analyze_domain_intelligence(
        from_header="Kajal <kajaltanu17.05@gmail.com>",
        reply_to_header="hacker@suspicious-domain.com",
        return_path_header=None,
        body_urls=["https://phishing-site.example.com/login"],
        offline_mode=True,
    )
    assert result["status"] == "success"
    assert result["signals"]["reply_to_mismatch"] is True
    assert result["signals"]["return_path_mismatch"] is False
    assert result["signals"]["body_domain_mismatch"] is True