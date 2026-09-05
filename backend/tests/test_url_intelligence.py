"""
Test Suite for ThreadLens URL Intelligence Module
Validates all 10 core requirements:
- Normal HTTPS URL
- HTTP URL
- Suspicious login URL
- URL containing IP address
- URL shortener
- Very long URL
- URL with @ symbol
- Punycode / IDN URL
- Malformed URL
- Multiple URLs in one email
"""

from url_intelligence import analyze_single_url, analyze_urls


def test_normal_https_url():
    url = "https://www.google.com/search?q=threadlens"
    result = analyze_single_url(url, sender_root="google.com")
    assert result["status"] == "success"
    assert result["risk_level"] == "LOW"
    assert result["risk_score"] < 30
    assert result["components"]["scheme"] == "https"
    assert result["hostname"] == "www.google.com"


def test_http_url():
    url = "http://example.com/about"
    result = analyze_single_url(url)
    assert result["status"] == "success"
    assert result["features"]["is_http_only"] is True
    assert "Unencrypted connection (HTTP instead of HTTPS)" in result["indicators"]


def test_suspicious_login_url():
    url = "https://secure-portal-update.com/account/login/verify"
    result = analyze_single_url(url, sender_root="legitimatebank.com")
    assert result["status"] == "success"
    assert result["risk_score"] >= 30
    assert any("keywords" in ind.lower() for ind in result["indicators"])
    assert "URL target domain does not match sender domain" in result["indicators"]


def test_ip_address_url():
    url = "http://192.168.1.50/admin"
    result = analyze_single_url(url)
    assert result["status"] == "success"
    assert result["features"]["is_ip_hostname"] is True
    assert any("IP address" in ind for ind in result["indicators"])
    assert result["risk_score"] >= 45


def test_url_shortener():
    url = "https://bit.ly/3xYz123"
    result = analyze_single_url(url)
    assert result["status"] == "success"
    assert result["features"]["is_shortener"] is True
    assert any("shortening service" in ind.lower() for ind in result["indicators"])


def test_very_long_url():
    url = "https://example.com/item?" + ("param=" + "a" * 120)
    result = analyze_single_url(url)
    assert result["status"] == "success"
    assert result["features"]["is_unusually_long"] is True
    assert any("Unusually long" in ind for ind in result["indicators"])


def test_at_symbol_url():
    url = "https://google.com@attacker-site.com/login"
    result = analyze_single_url(url)
    assert result["status"] == "success"
    assert result["features"]["has_at_symbol"] is True
    assert any("@" in ind for ind in result["indicators"])
    assert result["risk_score"] >= 40


def test_punycode_idn_url():
    url = "https://xn--pple-43d.com/support"
    result = analyze_single_url(url)
    assert result["status"] == "success"
    assert result["features"]["is_punycode"] is True
    assert any("Punycode" in ind for ind in result["indicators"])


def test_malformed_url():
    url = "http://:invalid::hostname"
    result = analyze_single_url(url)
    # Fails safely without raising an unhandled exception
    assert result["risk_score"] >= 0
    assert (
        result["status"] == "error"
        or "could not be safely parsed" in result["indicators"][0]
    )


def test_multiple_urls_aggregation():
    sample_urls = [
        "https://www.linkedin.com/feed/",
        "http://185.220.101.5/banking/login",
        "https://bit.ly/urgent-account-update",
    ]
    report = analyze_urls(sample_urls, sender_email="alerts@linkedin.com")

    assert report["summary"]["total_urls"] == 3
    assert report["summary"]["max_risk_score"] >= 60
    assert report["summary"]["overall_status"] in ["HIGH", "CRITICAL"]
    assert len(report["urls"]) == 3