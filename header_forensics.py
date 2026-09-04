import re
import dns.resolver
import ipaddress
import json
import sys

from email import policy
from email.parser import BytesParser


class HeaderForensicsEngine:
    """
    Module B: Header Forensics Engine

    Owner:
        Akankcha

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

        clean_addr = (
            match.group(1)
            if match
            else str(address).strip()
        )

        if "@" not in clean_addr:
            return None

        return (
            clean_addr
            .split("@")[-1]
            .strip()
            .lower()
        )

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

        # -----------------------------------------------------
        # SPF
        # -----------------------------------------------------

        try:

            txt_records = dns.resolver.resolve(
                domain,
                "TXT"
            )

            for record in txt_records:

                record_text = str(record).lower()

                if "v=spf1" in record_text:

                    records["spf_record"] = True
                    break

        except Exception:

            records["spf_record"] = False

        # -----------------------------------------------------
        # DMARC
        # -----------------------------------------------------

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

        # -----------------------------------------------------
        # Spoofing flag
        # -----------------------------------------------------

        is_spoofed = False

        # -----------------------------------------------------
        # Reply-To mismatch
        # -----------------------------------------------------

        if reply_to_domain and from_domain:

            if reply_to_domain != from_domain:

                is_spoofed = True

                anomalies.append({
                    "type": "REPLY_TO_MISMATCH",
                    "severity": "HIGH",
                    "details": (
                        f"Reply-To domain "
                        f"'{reply_to_domain}' "
                        f"does not match From domain "
                        f"'{from_domain}'"
                    )
                })

        # -----------------------------------------------------
        # Return-Path mismatch
        # -----------------------------------------------------

        if return_path_domain and from_domain:

            # Same domain OR valid subdomain
            is_related = (
                return_path_domain == from_domain
                or return_path_domain.endswith(
                    "." + from_domain
                )
            )

            if not is_related:

                anomalies.append({
                    "type": "RETURN_PATH_MISMATCH",
                    "severity": "MEDIUM",
                    "details": (
                        f"Return-Path domain "
                        f"'{return_path_domain}' "
                        f"does not match or belong to "
                        f"From domain "
                        f"'{from_domain}'"
                    )
                })

                # IMPORTANT:
                # Return-Path mismatch alone does NOT
                # prove spoofing.
                #
                # Many legitimate email providers use
                # separate bounce / mailing infrastructure.

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

        # -----------------------------------------------------
        # SPF
        # -----------------------------------------------------

        if re.search(
            r"\bspf\s*=\s*fail\b",
            auth_header
        ):

            spf = "FAIL"

        elif re.search(
            r"\bspf\s*=\s*pass\b",
            auth_header
        ):

            spf = "PASS"

        else:

            spf = "MISSING"

        # -----------------------------------------------------
        # DKIM
        # -----------------------------------------------------

        if re.search(
            r"\bdkim\s*=\s*fail\b",
            auth_header
        ):

            dkim = "FAIL"

        elif re.search(
            r"\bdkim\s*=\s*pass\b",
            auth_header
        ):

            dkim = "PASS"

        else:

            dkim = "MISSING"

        # -----------------------------------------------------
        # DMARC
        # -----------------------------------------------------

        if re.search(
            r"\bdmarc\s*=\s*fail\b",
            auth_header
        ):

            dmarc = "FAIL"

        elif re.search(
            r"\bdmarc\s*=\s*pass\b",
            auth_header
        ):

            dmarc = "PASS"

        else:

            dmarc = "MISSING"

        return {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "raw_auth_header": (
                auth_header
                if auth_header
                else None
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

        # -----------------------------------------------------
        # IPv4 + IPv6 candidate extraction
        # -----------------------------------------------------

        ip_pattern = re.compile(
            r"""
            (?:
                (?:\d{1,3}\.){3}\d{1,3}
                |
                (?:[0-9a-fA-F]{1,4}:){2,7}
                [0-9a-fA-F]{1,4}
            )
            """,
            re.VERBOSE
        )

        # -----------------------------------------------------
        # Process every Received header
        # -----------------------------------------------------

        for idx, header in enumerate(
            received_headers
        ):

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

                        # Avoid duplicate IPs in same hop
                        if ip_string not in valid_public_ips:

                            valid_public_ips.append(
                                ip_string
                            )

                        # Avoid duplicate IPs globally
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

        # -----------------------------------------------------
        # Origin IP candidate
        # -----------------------------------------------------

        origin_ip_candidate = (
            all_public_ips[-1]
            if all_public_ips
            else None
        )

        return {
            "total_hops": len(hops),
            "hop_chain": hops,
            "all_extracted_ips": all_public_ips,
            "origin_ip_candidate": origin_ip_candidate
        }

    # =========================================================
    # RISK SCORE
    # =========================================================

    def calculate_risk_score(
        self,
        identity,
        auth
    ):

        score = 0

        # -----------------------------------------------------
        # Identity anomalies
        # -----------------------------------------------------

        for anomaly in identity["anomalies"]:

            anomaly_type = anomaly["type"]

            # Reply-To mismatch is stronger signal
            if anomaly_type == "REPLY_TO_MISMATCH":

                score += 30

            # Return-Path mismatch is weaker signal
            elif anomaly_type == "RETURN_PATH_MISMATCH":

                score += 10

        # -----------------------------------------------------
        # Authentication failures
        # -----------------------------------------------------

        if auth["spf"] == "FAIL":

            score += 20

        if auth["dkim"] == "FAIL":

            score += 20

        if auth["dmarc"] == "FAIL":

            score += 20

        # -----------------------------------------------------
        # Limit score
        # -----------------------------------------------------

        return min(score, 100)

    # =========================================================
    # RISK SUMMARY
    # =========================================================

    def generate_risk_summary(self, score):

        if score >= 50:

            return (
                "CRITICAL: Strong spoofing or "
                "authentication failure indicators detected"
            )

        elif score > 0:

            return (
                "WARNING: Header anomalies or "
                "authentication issues detected"
            )

        else:

            return (
                "PASS: No significant header spoofing "
                "or authentication failures detected"
            )

    # =========================================================
    # MAIN HEADER FORENSICS ANALYSIS
    # =========================================================

    def generate_header_findings(self):

        # -----------------------------------------------------
        # Identity
        # -----------------------------------------------------

        identity = self.analyze_identity_spoofing()

        # -----------------------------------------------------
        # Authentication
        # -----------------------------------------------------

        auth = self.analyze_authentication_headers()

        # -----------------------------------------------------
        # Received / Network
        # -----------------------------------------------------

        hops = self.extract_received_hops()

        # -----------------------------------------------------
        # Live DNS
        # -----------------------------------------------------

        dns_status = self.check_live_dns_records(
            identity["from_domain"]
        )

        # -----------------------------------------------------
        # Calculate risk score
        # -----------------------------------------------------

        header_risk_score = self.calculate_risk_score(
            identity,
            auth
        )

        # -----------------------------------------------------
        # Generate summary
        # -----------------------------------------------------

        summary = self.generate_risk_summary(
            header_risk_score
        )

        # -----------------------------------------------------
        # Final output
        # -----------------------------------------------------

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


# =============================================================
# COMMAND LINE ENTRY POINT
# =============================================================

if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(
            "Usage: python header_forensics.py <email.eml>"
        )

        sys.exit(1)

    file_path = sys.argv[1]

    try:

        # -----------------------------------------------------
        # Parse EML file
        # -----------------------------------------------------

        with open(
            file_path,
            "rb"
        ) as f:

            msg = BytesParser(
                policy=policy.default
            ).parse(f)

        # -----------------------------------------------------
        # Run Header Forensics
        # -----------------------------------------------------

        engine = HeaderForensicsEngine(msg)

        result = engine.generate_header_findings()

        # -----------------------------------------------------
        # Print JSON
        # -----------------------------------------------------

        print(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=4
            )
        )

    except Exception as e:

        print(
            json.dumps(
                {
                    "error": str(e)
                },
                ensure_ascii=False,
                indent=4
            )
        )

        sys.exit(1)