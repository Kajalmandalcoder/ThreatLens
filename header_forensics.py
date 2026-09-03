import re
import dns.resolver
import ipaddress


class HeaderForensicsEngine:
    """
    Module B: Header Forensics Engine
    Owner: Akankcha

    Input:
        Parsed MIME Email Object

    Output:
        Structured Header Findings & Risk Analysis
    """

    def __init__(self, msg):
        self.msg = msg

    # =========================================================
    # DOMAIN EXTRACTION
    # =========================================================

    def _extract_domain(self, address):
        if not address:
            return None

        match = re.search(r"<([^>]+)>", str(address))
        clean_addr = match.group(1) if match else str(address).strip()

        if "@" not in clean_addr:
            return None

        return clean_addr.split("@")[-1].strip().lower()

    # =========================================================
    # LIVE DNS VERIFICATION
    # =========================================================

    def check_live_dns_records(self, domain):
        if not domain:
            return {
                "spf_record": False,
                "dmarc_record": False
            }

        records = {
            "spf_record": False,
            "dmarc_record": False
        }

        # -------------------------
        # SPF
        # -------------------------
        try:
            txt_records = dns.resolver.resolve(domain, "TXT")

            for record in txt_records:
                record_text = str(record).lower()

                if "v=spf1" in record_text:
                    records["spf_record"] = True
                    break

        except Exception:
            records["spf_record"] = False

        # -------------------------
        # DMARC
        # -------------------------
        try:
            dmarc_records = dns.resolver.resolve(
                f"_dmarc.{domain}",
                "TXT"
            )

            for record in dmarc_records:
                record_text = str(record).lower()

                if "v=dmarc1" in record_text:
                    records["dmarc_record"] = True
                    break

        except Exception:
            records["dmarc_record"] = False

        return records

    # =========================================================
    # FROM / REPLY-TO / RETURN-PATH ANALYSIS
    # =========================================================

    def analyze_identity_spoofing(self):

        from_domain = self._extract_domain(
            self.msg.get("From")
        )

        reply_to_domain = self._extract_domain(
            self.msg.get("Reply-To")
        )

        return_path_domain = self._extract_domain(
            self.msg.get("Return-Path")
        )

        anomalies = []
        is_spoofed = False

        # -------------------------
        # Reply-To mismatch
        # -------------------------
        if reply_to_domain and from_domain:

            if reply_to_domain != from_domain:

                is_spoofed = True

                anomalies.append({
                    "type": "REPLY_TO_MISMATCH",
                    "severity": "HIGH",
                    "details": (
                        f"Reply-To domain '{reply_to_domain}' "
                        f"does not match From domain '{from_domain}'"
                    )
                })

        # -------------------------
        # Return-Path mismatch
        # -------------------------
        if return_path_domain and from_domain:

            if return_path_domain != from_domain:

                is_spoofed = True

                anomalies.append({
                    "type": "RETURN_PATH_MISMATCH",
                    "severity": "MEDIUM",
                    "details": (
                        f"Return-Path domain '{return_path_domain}' "
                        f"does not match From domain '{from_domain}'"
                    )
                })

        return {
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
            "is_spoofed": is_spoofed,
            "anomalies": anomalies
        }

    # =========================================================
    # SPF / DKIM / DMARC
    # =========================================================

    def analyze_authentication_headers(self):

        auth_headers = self.msg.get_all(
            "Authentication-Results",
            []
        )

        auth_header = " ".join(
            str(header)
            for header in auth_headers
        ).lower()

        # SPF
        if re.search(r"\bspf\s*=\s*fail\b", auth_header):
            spf = "FAIL"
        elif re.search(r"\bspf\s*=\s*pass\b", auth_header):
            spf = "PASS"
        else:
            spf = "MISSING"

        # DKIM
        if re.search(r"\bdkim\s*=\s*fail\b", auth_header):
            dkim = "FAIL"
        elif re.search(r"\bdkim\s*=\s*pass\b", auth_header):
            dkim = "PASS"
        else:
            dkim = "MISSING"

        # DMARC
        if re.search(r"\bdmarc\s*=\s*fail\b", auth_header):
            dmarc = "FAIL"
        elif re.search(r"\bdmarc\s*=\s*pass\b", auth_header):
            dmarc = "PASS"
        else:
            dmarc = "MISSING"

        return {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "raw_auth_header": (
                auth_header if auth_header else None
            )
        }

    # =========================================================
    # EXTRACT RECEIVED HEADERS + NETWORK HOPS + IPs
    # =========================================================

    def extract_received_hops(self):

        received_headers = self.msg.get_all(
            "Received",
            []
        )

        hops = []
        all_public_ips = []

        # IPv4 + IPv6 candidate extraction
        ip_pattern = re.compile(
            r"""
            (?:
                (?:\d{1,3}\.){3}\d{1,3}
                |
                (?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}
            )
            """,
            re.VERBOSE
        )

        for idx, header in enumerate(received_headers):

            raw_header = str(header).strip()

            candidates = ip_pattern.findall(
                raw_header
            )

            valid_public_ips = []

            for candidate in candidates:

                try:
                    ip_obj = ipaddress.ip_address(
                        candidate
                    )

                    # Only globally routable IPs
                    if ip_obj.is_global:

                        ip_string = str(ip_obj)

                        if ip_string not in valid_public_ips:
                            valid_public_ips.append(
                                ip_string
                            )

                        if ip_string not in all_public_ips:
                            all_public_ips.append(
                                ip_string
                            )

                except ValueError:
                    # Ignore invalid IP candidates
                    continue

            hops.append({
                "hop_id": idx + 1,
                "raw_received": raw_header,
                "extracted_public_ips": valid_public_ips
            })

        return {
            "total_hops": len(hops),
            "hop_chain": hops,
            "all_extracted_ips": all_public_ips,

            # This is a candidate only.
            # It should NOT be treated as confirmed sender IP.
            "origin_ip_candidate": (
                all_public_ips[-1]
                if all_public_ips
                else None
            )
        }

    # =========================================================
    # MAIN HEADER FORENSICS ANALYSIS
    # =========================================================

    def generate_header_findings(self):

        # -------------------------
        # Identity
        # -------------------------
        identity = self.analyze_identity_spoofing()

        # -------------------------
        # Authentication
        # -------------------------
        auth = self.analyze_authentication_headers()

        # -------------------------
        # Received / Network
        # -------------------------
        hops = self.extract_received_hops()

        # -------------------------
        # Live DNS
        # -------------------------
        dns_status = self.check_live_dns_records(
            identity["from_domain"]
        )

        # =====================================================
        # RISK SCORE
        # =====================================================

        header_risk_score = 0

        if identity["is_spoofed"]:
            header_risk_score += 45

        if auth["spf"] == "FAIL":
            header_risk_score += 20

        if auth["dkim"] == "FAIL":
            header_risk_score += 20

        if auth["dmarc"] == "FAIL":
            header_risk_score += 15

        header_risk_score = min(
            header_risk_score,
            100
        )

        # =====================================================
        # SUMMARY
        # =====================================================

        if header_risk_score >= 40:

            summary = (
                "CRITICAL: Spoofing or Authentication "
                "Failures Detected"
            )

        elif header_risk_score > 0:

            summary = (
                "WARNING: Header Anomalies Detected"
            )

        else:

            summary = (
                "PASS: No header spoofing or "
                "authentication failures detected"
            )

        # =====================================================
        # FINAL OUTPUT
        # =====================================================

        return {

            "module": "B. HEADER FORENSICS",

            "owner": "Akankcha",

            "header_risk_score": header_risk_score,

            "identity_analysis": identity,

            "authentication_matrix": auth,

            "live_dns_verification": dns_status,

            "network_hops": hops,

            "header_findings_summary": summary
        }