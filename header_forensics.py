import re
import dns.exception
import dns.resolver
import ipaddress
import json
import sys

from email import policy
from email.parser import BytesParser


class HeaderForensicsEngine:
    """
    ThreadLens - Module B: Header Forensics

    Responsibilities:
    - From / Reply-To / Return-Path domain analysis
    - Authentication-Results analysis
    - SPF / DKIM / DMARC status
    - Live DNS verification
    - Received header parsing
    - IPv4 / IPv6 extraction
    - Public-origin IP candidate detection
    - Explainable header risk scoring
    """

    # =========================================================
    # INIT
    # =========================================================

    def __init__(self, msg):
        self.msg = msg

    # =========================================================
    # DOMAIN EXTRACTION
    # =========================================================

    def _extract_domain(self, address):
        """
        Extract domain from an email header.

        Examples:
            John Doe <john@example.com>
            john@example.com

        Returns:
            example.com
            None
        """

        if not address:
            return None

        try:
            raw = str(address).strip()

            # Extract address from <...>
            match = re.search(
                r"<\s*([^>]+)\s*>",
                raw
            )

            clean_address = (
                match.group(1).strip()
                if match
                else raw
            )

            if "@" not in clean_address:
                return None

            domain = (
                clean_address
                .rsplit("@", 1)[-1]
                .strip()
                .lower()
            )

            # Remove accidental trailing >
            domain = domain.rstrip(">")

            if not domain:
                return None

            return domain

        except Exception:
            return None

    # =========================================================
    # DNS RESOLVER
    # =========================================================

    def _build_resolver(self, timeout_sec=3.0):
        resolver = dns.resolver.Resolver()

        resolver.timeout = timeout_sec
        resolver.lifetime = timeout_sec

        return resolver

    # =========================================================
    # SPF / DMARC LIVE DNS
    # =========================================================

    def check_live_dns_records(self, domain):
        """
        Dynamically verify SPF and DMARC records.

        Returns:
            True  -> record exists
            False -> lookup succeeded but record absent
            None  -> lookup unavailable
        """

        result = {
            "spf_record": None,
            "dmarc_record": None
        }

        if not domain:
            return result

        # -----------------------------------------------------
        # SPF
        # -----------------------------------------------------

        result["spf_record"] = self._check_spf(domain)

        # -----------------------------------------------------
        # DMARC
        # -----------------------------------------------------

        result["dmarc_record"] = self._check_dmarc(domain)

        return result

    # =========================================================
    # SPF CHECK
    # =========================================================

    def _check_spf(self, domain, timeout_sec=3.0):
        """
        Check TXT records for v=spf1.

        System resolver is tried first.
        Cloudflare / Google DNS are used as fallback.
        """

        if not domain:
            return None

        resolvers = []

        # System resolver
        try:
            system_resolver = self._build_resolver(
                timeout_sec
            )
            resolvers.append(system_resolver)
        except Exception:
            pass

        # Public DNS fallback
        for nameserver in [
            "1.1.1.1",
            "8.8.8.8"
        ]:
            try:
                resolver = dns.resolver.Resolver(
                    configure=False
                )

                resolver.nameservers = [
                    nameserver
                ]

                resolver.timeout = timeout_sec
                resolver.lifetime = timeout_sec

                resolvers.append(resolver)

            except Exception:
                continue

        successful_lookup = False

        for resolver in resolvers:

            try:
                answers = resolver.resolve(
                    domain,
                    "TXT"
                )

                successful_lookup = True

                for record in answers:

                    try:
                        record_text = record.to_text()
                    except Exception:
                        record_text = str(record)

                    normalized = (
                        record_text
                        .strip()
                        .replace('"', "")
                        .lower()
                    )

                    if re.search(
                        r"(^|\s)v=spf1(?:\s|$)",
                        normalized
                    ):
                        return True

            except dns.resolver.NXDOMAIN:
                successful_lookup = True
                continue

            except dns.resolver.NoAnswer:
                successful_lookup = True
                continue

            except (
                dns.resolver.NoNameservers,
                dns.exception.Timeout
            ):
                continue

            except Exception:
                continue

        if successful_lookup:
            return False

        return None

    # =========================================================
    # DMARC CHECK
    # =========================================================

    def _check_dmarc(self, domain, timeout_sec=3.0):
        """
        Check _dmarc.<domain> TXT records.
        """

        if not domain:
            return None

        dmarc_domain = (
            f"_dmarc.{domain}"
        )

        resolver = self._build_resolver(
            timeout_sec
        )

        try:
            answers = resolver.resolve(
                dmarc_domain,
                "TXT"
            )

            for record in answers:

                try:
                    record_text = record.to_text()
                except Exception:
                    record_text = str(record)

                normalized = (
                    record_text
                    .strip()
                    .replace('"', "")
                    .lower()
                )

                if normalized.startswith(
                    "v=dmarc1"
                ):
                    return True

            return False

        except dns.resolver.NXDOMAIN:
            return False

        except dns.resolver.NoAnswer:
            return False

        except (
            dns.resolver.NoNameservers,
            dns.exception.Timeout
        ):
            return None

        except Exception:
            return None

    # =========================================================
    # IDENTITY ANALYSIS
    # =========================================================

    def analyze_identity_spoofing(self):
        """
        Compare From, Reply-To and Return-Path.

        Important:
        Missing Reply-To / Return-Path is NOT a mismatch.

        Return-Path mismatch is a warning signal,
        but alone does not prove spoofing.
        """

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

        # -----------------------------------------------------
        # Reply-To mismatch
        # -----------------------------------------------------

        if (
            from_domain
            and reply_to_domain
        ):
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

        if (
            from_domain
            and return_path_domain
        ):

            # Root domain exact match
            # OR legitimate subdomain relation
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

        return {
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
            "is_spoofed": is_spoofed,
            "anomalies": anomalies
        }

    # =========================================================
    # AUTHENTICATION HEADERS
    # =========================================================

    def analyze_authentication_headers(self):
        """
        Parse Authentication-Results.

        States:
            PASS
            FAIL
            MISSING
        """

        auth_headers = self.msg.get_all(
            "Authentication-Results",
            []
        )

        raw_auth_header = " ".join(
            str(header)
            for header in auth_headers
        )

        auth_header = raw_auth_header.lower()

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

        elif re.search(
            r"\bspf\s*=\s*(?:softfail|neutral|none|temperror|permerror)\b",
            auth_header
        ):
            spf = "MISSING"

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

        elif re.search(
            r"\bdkim\s*=\s*(?:neutral|none|temperror|permerror)\b",
            auth_header
        ):
            dkim = "MISSING"

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

        elif re.search(
            r"\bdmarc\s*=\s*(?:neutral|none|temperror|permerror)\b",
            auth_header
        ):
            dmarc = "MISSING"

        else:
            dmarc = "MISSING"

        return {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "raw_auth_header": (
                raw_auth_header
                if raw_auth_header
                else None
            )
        }

    # =========================================================
    # RECEIVED HEADER / IP EXTRACTION
    # =========================================================

    def extract_received_hops(self):
        """
        Parse Received headers.

        Extract only globally routable IPs.

        Private, loopback, link-local,
        multicast and documentation ranges are excluded.
        """

        received_headers = self.msg.get_all(
            "Received",
            []
        )

        hops = []

        all_public_ips = []

        # -----------------------------------------------------
        # IPv4 / IPv6 patterns
        # -----------------------------------------------------

        ip_pattern = re.compile(
            r"""
            # IPv4
            (?<![A-Za-z0-9])
            (
                (?:\d{1,3}\.){3}\d{1,3}
            )
            (?![A-Za-z0-9])

            |

            # IPv6
            (?<![A-Za-z0-9])
            (
                (?:
                    [0-9A-Fa-f]{1,4}
                    :
                ){2,7}
                [0-9A-Fa-f:.]*
            )
            (?![A-Za-z0-9])
            """,
            re.VERBOSE
        )

        # -----------------------------------------------------
        # Process headers
        # -----------------------------------------------------

        for idx, header in enumerate(
            received_headers
        ):

            raw_header = str(
                header
            ).strip()

            candidates = []

            # -------------------------------------------------
            # Regular matches
            # -------------------------------------------------

            for match in ip_pattern.finditer(
                raw_header
            ):

                ipv4 = match.group(1)
                ipv6 = match.group(2)

                candidate = (
                    ipv4
                    or ipv6
                )

                if candidate:
                    candidates.append(
                        candidate
                    )

            # -------------------------------------------------
            # Bracketed IPv6 support
            # -------------------------------------------------

            bracketed_ipv6_pattern = re.compile(
                r"\[([0-9A-Fa-f:]+)\]"
            )

            for match in bracketed_ipv6_pattern.finditer(
                raw_header
            ):

                candidate = match.group(1)

                if candidate:
                    candidates.append(
                        candidate
                    )

            # -------------------------------------------------
            # Validate public IPs
            # -------------------------------------------------

            valid_public_ips = []

            for candidate in candidates:

                try:
                    ip_obj = ipaddress.ip_address(
                        candidate
                    )

                except ValueError:
                    continue

                # Only globally routable
                if not ip_obj.is_global:
                    continue

                ip_string = str(
                    ip_obj
                )

                # Same-hop dedupe
                if ip_string not in valid_public_ips:

                    valid_public_ips.append(
                        ip_string
                    )

                # Global dedupe
                if ip_string not in all_public_ips:

                    all_public_ips.append(
                        ip_string
                    )

            # -------------------------------------------------
            # Store hop
            # -------------------------------------------------

            hops.append({
                "hop_id": idx + 1,
                "raw_received": raw_header,
                "extracted_public_ips":
                    valid_public_ips
            })

        # -----------------------------------------------------
        # Origin candidate
        #
        # Received headers generally run newest -> oldest.
        # Last globally extracted public IP is used as candidate.
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
            "origin_ip_candidate":
                origin_ip_candidate
        }

    # =========================================================
    # RISK SCORE
    # =========================================================

    def calculate_risk_score(
        self,
        identity,
        auth
    ):
        """
        Header risk scoring.

        Identity:
            Reply-To mismatch      +30
            Return-Path mismatch   +10

        Authentication:
            SPF FAIL               +20
            DKIM FAIL              +20
            DMARC FAIL             +20

            SPF missing            +5
            DKIM missing           +5
            DMARC missing          +5

        Maximum:
            100
        """

        score = 0

        # -----------------------------------------------------
        # Identity anomalies
        # -----------------------------------------------------

        for anomaly in identity.get(
            "anomalies",
            []
        ):

            anomaly_type = anomaly.get(
                "type"
            )

            if anomaly_type == (
                "REPLY_TO_MISMATCH"
            ):
                score += 30

            elif anomaly_type == (
                "RETURN_PATH_MISMATCH"
            ):
                score += 10

        # -----------------------------------------------------
        # Authentication FAIL
        # -----------------------------------------------------

        if auth.get("spf") == "FAIL":
            score += 20

        if auth.get("dkim") == "FAIL":
            score += 20

        if auth.get("dmarc") == "FAIL":
            score += 20

        # -----------------------------------------------------
        # Authentication MISSING
        # -----------------------------------------------------

        if auth.get("spf") == "MISSING":
            score += 5

        if auth.get("dkim") == "MISSING":
            score += 5

        if auth.get("dmarc") == "MISSING":
            score += 5

        return min(
            max(score, 0),
            100
        )

    # =========================================================
    # RISK SUMMARY
    # =========================================================

    def generate_risk_summary(
        self,
        score,
        auth,
        identity
    ):
        """
        Generate human-readable header summary.
        """

        has_auth_failure = any(
            auth.get(field) == "FAIL"
            for field in [
                "spf",
                "dkim",
                "dmarc"
            ]
        )

        missing_auth_fields = [
            field.upper()
            for field in [
                "spf",
                "dkim",
                "dmarc"
            ]
            if auth.get(field) == "MISSING"
        ]

        has_identity_anomaly = bool(
            identity.get(
                "anomalies",
                []
            )
        )

        # -----------------------------------------------------
        # Critical
        # -----------------------------------------------------

        if score >= 50:
            return (
                "CRITICAL: Strong spoofing or "
                "authentication failure indicators detected"
            )

        # -----------------------------------------------------
        # Authentication failure
        # -----------------------------------------------------

        if has_auth_failure:

            return (
                "WARNING: Authentication failure "
                "indicators detected"
            )

        # -----------------------------------------------------
        # Identity anomaly
        # -----------------------------------------------------

        if has_identity_anomaly:

            if missing_auth_fields:

                return (
                    "WARNING: Header identity anomaly detected; "
                    "some authentication signals are missing"
                )

            return (
                "WARNING: Header identity anomaly detected"
            )

        # -----------------------------------------------------
        # Missing auth
        # -----------------------------------------------------

        if missing_auth_fields:

            fields = ", ".join(
                missing_auth_fields
            )

            return (
                "WARNING: Some email authentication "
                f"signals are missing ({fields})"
            )

        # -----------------------------------------------------
        # Clean
        # -----------------------------------------------------

        if score == 0:

            return (
                "PASS: No significant header risk "
                "indicators detected"
            )

        return (
            "WARNING: Header anomalies detected"
        )

    # =========================================================
    # MAIN
    # =========================================================

    def generate_header_findings(self):
        """
        Main Header Forensics pipeline.
        """

        # -----------------------------------------------------
        # Identity
        # -----------------------------------------------------

        identity = (
            self.analyze_identity_spoofing()
        )

        # -----------------------------------------------------
        # Authentication
        # -----------------------------------------------------

        auth = (
            self.analyze_authentication_headers()
        )

        # -----------------------------------------------------
        # Received headers
        # -----------------------------------------------------

        hops = (
            self.extract_received_hops()
        )

        # -----------------------------------------------------
        # Live DNS
        # -----------------------------------------------------

        dns_status = (
            self.check_live_dns_records(
                identity.get(
                    "from_domain"
                )
            )
        )

        # -----------------------------------------------------
        # Risk
        # -----------------------------------------------------

        header_risk_score = (
            self.calculate_risk_score(
                identity,
                auth
            )
        )

        # -----------------------------------------------------
        # Summary
        # -----------------------------------------------------

        summary = (
            self.generate_risk_summary(
                header_risk_score,
                auth,
                identity
            )
        )

        # -----------------------------------------------------
        # Final structured output
        # -----------------------------------------------------

        return {
            "module": "B. HEADER FORENSICS",

            "owner": "Akankcha",

            "header_risk_score":
                header_risk_score,

            "identity_analysis": identity,

            "authentication_matrix": auth,

            "live_dns_verification": dns_status,

            "network_hops": hops,

            "header_findings_summary":
                summary
        }


# =============================================================
# CLI ENTRY POINT
# =============================================================

if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(
            json.dumps(
                {
                    "error":
                        "Usage: python header_forensics.py <email.eml>"
                },
                ensure_ascii=False,
                indent=4
            )
        )

        sys.exit(1)

    file_path = sys.argv[1]

    try:

        # -----------------------------------------------------
        # Parse EML
        # -----------------------------------------------------

        with open(
            file_path,
            "rb"
        ) as file:

            msg = BytesParser(
                policy=policy.default
            ).parse(file)

        # -----------------------------------------------------
        # Run engine
        # -----------------------------------------------------

        engine = HeaderForensicsEngine(
            msg
        )

        result = (
            engine.generate_header_findings()
        )

        # -----------------------------------------------------
        # JSON output
        # -----------------------------------------------------

        print(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=4
            )
        )

    except Exception as exc:

        print(
            json.dumps(
                {
                    "error":
                        str(exc)
                },
                ensure_ascii=False,
                indent=4
            )
        )

        sys.exit(1)