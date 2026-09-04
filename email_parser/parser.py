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

        "attachments": attachments
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