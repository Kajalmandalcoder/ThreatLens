"""
ThreadLens - Test IP & Domain Intelligence directly on .eml files
"""

import email
from email import policy
import ipaddress
import os
from pprint import pprint
import re
from intelligence import process_intelligence_pipeline


def parse_eml_to_pipeline_format(eml_path: str) -> dict:
    """Reads a raw .eml file and extracts headers and links for the intelligence pipeline."""
    if not os.path.exists(eml_path):
        raise FileNotFoundError(f"File not found: {eml_path}")

    with open(eml_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    # 1. Extract Core Headers
    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", None)
    return_path = msg.get("Return-Path", None)
    subject = msg.get("Subject", "(No Subject)")
    received_headers = msg.get_all("Received", [])

    # 2. Extract strictly valid IPv4 addresses from Received headers
    raw_ip_matches = []
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

    for hop in received_headers:
        matches = re.findall(ip_pattern, str(hop))
        for candidate in matches:
            try:
                # Discard fake timestamp matches like '026.08.10.00'
                parsed_ip = ipaddress.ip_address(candidate)
                if (
                    isinstance(parsed_ip, ipaddress.IPv4Address)
                    and candidate not in raw_ip_matches
                ):
                    raw_ip_matches.append(candidate)
            except ValueError:
                continue

    # Origin candidate: find the earliest valid public hop (bottom-up)
    origin_ip = None
    for candidate in reversed(raw_ip_matches):
        try:
            ip_obj = ipaddress.ip_address(candidate)
            if not (
                ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
            ):
                origin_ip = candidate
                break
        except ValueError:
            continue

    if not origin_ip and raw_ip_matches:
        origin_ip = raw_ip_matches[-1]

    # 3. Extract URLs from Plain Text and HTML Body
    body_text = ""
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type in ["text/plain", "text/html"]:
            try:
                body_text += part.get_payload(decode=True).decode(
                    errors="ignore"
                )
            except Exception:
                pass

    # Search for all http/https URLs in the body
    url_pattern = r'https?://[^\s"\'<>]+'
    extracted_urls = list(set(re.findall(url_pattern, body_text)))

    # 4. Return matching format for our pipeline
    return {
        "headers": {
            "from": from_header,
            "replyTo": reply_to,
            "returnPath": return_path,
            "subject": subject,
            "received": received_headers,
        },
        "links": extracted_urls,
        "headerForensics": {
            "network_hops": {
                "origin_ip_candidate": origin_ip,
                "all_extracted_ips": raw_ip_matches,
            }
        },
    }


def analyze_single_eml(eml_relative_path: str):
    """Helper function to parse and display intelligence for a single .eml file."""
    print(f"\n{'='*70}")
    print(f"ANALYZING: {eml_relative_path}")
    print(f"{'='*70}")

    doc = parse_eml_to_pipeline_format(eml_relative_path)

    print(f"Subject: {doc['headers']['subject']}")
    print(f"From:    {doc['headers']['from']}")
    print(
        f"Origin IP Candidate: {doc['headerForensics']['network_hops']['origin_ip_candidate']}"
    )
    print(
        f"Extracted IPs:       {doc['headerForensics']['network_hops']['all_extracted_ips']}"
    )
    print(f"Found {len(doc['links'])} body links.")

    # Run Intelligence Modules
    results = process_intelligence_pipeline(doc, offline_mode=False)

    print("\n--- DOMAIN INTELLIGENCE ---")
    pprint(results["domain_intelligence"])

    print("\n--- IP INTELLIGENCE ---")
    pprint(results["ip_intelligence"])

    print("\n--- FINAL FORENSIC SIGNALS ---")
    pprint(results["intelligence_signals"])


def test_all_local_emls():
    """Pytest test case: verifies local sample .eml files parse cleanly."""
    files = [
        "email_parser/emails/Application Support Engineer at Accenture in India.eml",
        "email_parser/emails/Invitation to MongoDB Cloud_ Himanshi's Org - 2026-09-01.eml",
    ]
    for eml_file in files:
        if os.path.exists(eml_file):
            doc = parse_eml_to_pipeline_format(eml_file)
            result = process_intelligence_pipeline(doc, offline_mode=True)
            assert result["domain_intelligence"]["status"] == "success"
            assert "intelligence_signals" in result


if __name__ == "__main__":
    files_to_test = [
        "email_parser/emails/Application Support Engineer at Accenture in India.eml",
        "email_parser/emails/Invitation to MongoDB Cloud_ Himanshi's Org - 2026-09-01.eml",
    ]

    for eml_file in files_to_test:
        if os.path.exists(eml_file):
            analyze_single_eml(eml_file)
        else:
            print(f"\n[!] File not found: {eml_file}")