from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
import re
import json
import sys
import base64
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")
from pathlib import Path
from urllib.parse import urlparse

def parse_email_journey(received_headers):

    journey = []

    for index, received in enumerate(received_headers, start=1):

        hop = {
            "hop_id": index,
            "from": None,
            "by": None,
            "ip": None,
            "timestamp": None
        }

        # -----------------------------
        # Extract FROM server
        # -----------------------------

        from_match = re.search(
            r'\bfrom\s+([^\s(]+)',
            received,
            re.IGNORECASE
        )

        if from_match:
            from_server = from_match.group(1)

            # Don't treat IP address as server name
            if not re.fullmatch(r'[0-9a-fA-F:.]+', from_server):
                hop["from"] = from_server

        # -----------------------------
        # Extract BY server
        # -----------------------------

        by_match = re.search(
            r'\bby\s+([^\s;]+)',
            received,
            re.IGNORECASE
        )

        if by_match:
            by_server = by_match.group(1)

            # Don't treat IP address as server name
            if not re.fullmatch(r'[0-9a-fA-F:.]+', by_server):
                hop["by"] = by_server

        # -----------------------------
        # Extract IP address
        # -----------------------------

        # IP inside [ ]
        ip_match = re.search(
            r'\[([0-9a-fA-F:.]+)\]',
            received
        )

        if ip_match:
            hop["ip"] = ip_match.group(1)

        # If IP is not inside [ ], check FROM
        if hop["ip"] is None:
            if from_match:
                candidate = from_match.group(1)

                if re.fullmatch(r'[0-9a-fA-F:.]+', candidate):
                    hop["ip"] = candidate

        # If still no IP, check BY
        if hop["ip"] is None:
            if by_match:
                candidate = by_match.group(1)

                if re.fullmatch(r'[0-9a-fA-F:.]+', candidate):
                    hop["ip"] = candidate

        # -----------------------------
        # Extract timestamp
        # -----------------------------

        timestamp_match = re.search(
            r'([A-Z][a-z]{2},\s+\d{1,2}\s+[A-Z][a-z]{2}\s+\d{4}\s+'
            r'\d{2}:\d{2}:\d{2}\s+[+-]\d{4})',
            received
        )

        if timestamp_match:
            hop["timestamp"] = timestamp_match.group(1)

        journey.append(hop)

    return journey


def parse_email(file_path):

    # ---------------------------------
    # READ EML FILE
    # ---------------------------------

    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # ---------------------------------
    # BASIC EMAIL HEADERS
    # ---------------------------------

    headers = {
        "from": msg.get("From"),
        "to": msg.get("To"),
        "cc": msg.get("Cc"),
        "bcc": msg.get("Bcc"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "messageId": msg.get("Message-ID"),
        "replyTo": msg.get("Reply-To"),
        "returnPath": msg.get("Return-Path"),
        "received": msg.get_all("Received", [])
    }

    # ---------------------------------
    # EMAIL JOURNEY
    # ---------------------------------

    email_journey = {
        "hops": parse_email_journey(headers["received"])
    }

    # ---------------------------------
    # EMAIL BODY
    # ---------------------------------

    plain_text = ""
    html_text = ""

    for part in msg.walk():

        content_type = part.get_content_type()

        if content_type == "text/plain":
            try:
                plain_text += part.get_content()
            except Exception:
                pass

        elif content_type == "text/html":
            try:
                html_text += part.get_content()
            except Exception:
                pass

    # ---------------------------------
    # EXTRACT LINKS
    # ---------------------------------

    urls = set()

    # URLs from plain text
    plain_urls = re.findall(
        r'https?://[^\s<>"\'\]]+',
        plain_text
    )

    for url in plain_urls:
        urls.add(url)

    # URLs from HTML href
    if html_text:

        soup = BeautifulSoup(
            html_text,
            "html.parser"
        )

        for link in soup.find_all("a", href=True):

            href = link["href"]

            if href.startswith(("http://", "https://")):
                urls.add(href)

    # Convert links to structured list
    links = []

    for url in sorted(urls):

        parsed_url = urlparse(url)

        domain = parsed_url.netloc

        links.append({
            "url": url,
            "domain": domain
        })

    # ---------------------------------
    # EXTRACT ATTACHMENTS
    # ---------------------------------

    attachments = []

    for part in msg.walk():

        filename = part.get_filename()

        if filename:

            payload = part.get_payload(decode=True)

            # Convert binary payload to Base64 string for JSON safety
            encoded_content = base64.b64encode(payload).decode("utf-8") if payload else ""

            attachment = {
                "filename": filename,
                "contentType": part.get_content_type(),
                "size": len(payload) if payload else 0,
                "content": encoded_content
            }

            attachments.append(attachment)

    # ---------------------------------
    # FINAL STRUCTURED EMAIL DATA
    # ---------------------------------

    result = {
        "headers": headers,

        "body": {
            "plainText": plain_text,
            "html": html_text
        },

        "links": links,

        "attachments": attachments,

        "emailJourney": email_journey
    }

    return result


# =================================
# COMMAND LINE ENTRY POINT
# =================================

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print(json.dumps({"error": "No .eml file provided"}, indent=4))
        sys.exit(1)

    file_path = Path(sys.argv[1])

    if not file_path.exists():
        print(json.dumps({"error": f"File not found: {file_path}"}, indent=4))
        sys.exit(1)

    try:
        result = parse_email(file_path)
        formatted_json = json.dumps(result, ensure_ascii=False, indent=4)
        sys.stdout.write(formatted_json)
        sys.stdout.write("\n")

    except Exception as e:
        print(json.dumps({"error": str(e)}, indent=4))
        sys.exit(1)