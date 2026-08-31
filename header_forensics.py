import re
import dns.resolver
from urllib.parse import urlparse

class HeaderForensicsEngine:
    """
    Module B: Header Forensics Engine
    Owner: Akankcha
    Input: Parsed MIME Email Object
    Output: Structured Header Findings & Risk Analysis
    """
    def __init__(self, msg):
        self.msg = msg

    def _extract_domain(self, address):
        if not address:
            return None
        match = re.search(r'<([^>]+)>', str(address))
        clean_addr = match.group(1) if match else str(address).strip()
        return clean_addr.split('@')[-1].lower() if '@' in clean_addr else None

    # LIVE DNS CHECK METHOD
    def check_live_dns_records(self, domain):
        if not domain:
            return {"spf_record": False, "dmarc_record": False}
        
        records = {"spf_record": False, "dmarc_record": False}
        
        # Live SPF Lookup
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for record in txt_records:
                if "v=spf1" in str(record):
                    records["spf_record"] = True
                    break
        except Exception:
            records["spf_record"] = False

        # Live DMARC Lookup
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for record in dmarc_records:
                if "v=DMARC1" in str(record):
                    records["dmarc_record"] = True
                    break
        except Exception:
            records["dmarc_record"] = False

        return records

    def analyze_identity_spoofing(self):
        from_domain = self._extract_domain(self.msg.get("From"))
        reply_to_domain = self._extract_domain(self.msg.get("Reply-To"))
        return_path_domain = self._extract_domain(self.msg.get("Return-Path"))

        anomalies = []
        is_spoofed = False

        if reply_to_domain and (from_domain != reply_to_domain):
            is_spoofed = True
            anomalies.append({
                "type": "REPLY_TO_MISMATCH",
                "severity": "HIGH",
                "details": f"Reply-To domain '{reply_to_domain}' does not match From domain '{from_domain}'"
            })

        if return_path_domain and (from_domain != return_path_domain):
            is_spoofed = True
            anomalies.append({
                "type": "RETURN_PATH_MISMATCH",
                "severity": "MEDIUM",
                "details": f"Return-Path domain '{return_path_domain}' does not match From domain '{from_domain}'"
            })

        return {
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
            "is_spoofed": is_spoofed,
            "anomalies": anomalies
        }

    def analyze_authentication_headers(self):
        auth_header = str(self.msg.get("Authentication-Results", "")).lower()

        spf = "FAIL" if "spf=fail" in auth_header else ("PASS" if "spf=pass" in auth_header else "MISSING")
        dkim = "FAIL" if "dkim=fail" in auth_header else ("PASS" if "dkim=pass" in auth_header else "MISSING")
        dmarc = "FAIL" if "dmarc=fail" in auth_header else ("PASS" if "dmarc=pass" in auth_header else "MISSING")

        return {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "raw_auth_header": auth_header if auth_header else None
        }

    def extract_received_hops(self):
        received_headers = self.msg.get_all("Received", [])
        hops = []
        public_ips = []

        if received_headers:
            for idx, header in enumerate(received_headers):
                extracted_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(header))
                non_private = [ip for ip in extracted_ips if not ip.startswith(("10.", "172.16.", "192.168.", "127."))]
                
                public_ips.extend(non_private)
                hops.append({
                    "hop_id": idx + 1,
                    "raw_received": str(header).strip(),
                    "extracted_public_ips": non_private
                })

        return {
            "total_hops": len(hops),
            "hop_chain": hops,
            "all_extracted_ips": public_ips,
            "origin_ip_candidate": public_ips[-1] if public_ips else None
        }

    def generate_header_findings(self):
        identity = self.analyze_identity_spoofing()
        auth = self.analyze_authentication_headers()
        hops = self.extract_received_hops()
        
        # Live DNS check for the Sender Domain
        dns_status = self.check_live_dns_records(identity["from_domain"])

        header_risk_score = 0
        if identity["is_spoofed"]: 
            header_risk_score += 45
        if auth["spf"] == "FAIL": 
            header_risk_score += 20
        if auth["dkim"] == "FAIL": 
            header_risk_score += 20
        if auth["dmarc"] == "FAIL": 
            header_risk_score += 15

        header_risk_score = min(header_risk_score, 100)

        return {
            "module": "B. HEADER FORENSICS",
            "owner": "Akankcha",
            "header_risk_score": header_risk_score,
            "identity_analysis": identity,
            "authentication_matrix": auth,
            "live_dns_verification": dns_status,
            "network_hops": hops,
            "header_findings_summary": (
                "CRITICAL: Spoofing or Auth Failures Detected" 
                if header_risk_score >= 40 
                else "PASS: Headers are authentic"
            )
        }