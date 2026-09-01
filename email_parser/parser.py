from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
import re
import json
import sys
from pathlib import Path


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
        "returnPath": msg.get("Return-Path")
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
        r'https?://[^\s<>"\']+',
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

    # Convert links to list
    links = []

    for url in sorted(urls):

        links.append({
            "url": url
        })

    # ---------------------------------
    # EXTRACT ATTACHMENTS
    # ---------------------------------
    attachments = []

    for part in msg.walk():

        filename = part.get_filename()

        if filename:

            payload = part.get_payload(
                decode=True
            )

            attachment = {
                "filename": filename,
                "contentType": part.get_content_type(),
                "size": len(payload) if payload else 0
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

    # Check whether .eml file was provided
    if len(sys.argv) < 2:

        print(
            json.dumps(
                {
                    "error": "No .eml file provided"
                },
                indent=4
            )
        )

        sys.exit(1)

    # Get file path from command line
    file_path = Path(sys.argv[1])

    # Check file exists
    if not file_path.exists():

        print(
            json.dumps(
                {
                    "error": f"File not found: {file_path}"
                },
                indent=4
            )
        )

        sys.exit(1)

    # Parse email
    try:

        result = parse_email(file_path)

        # Convert result to formatted JSON
        formatted_json = json.dumps(
            result,
            ensure_ascii=False,
            indent=4
        )

        # Print formatted JSON
        sys.stdout.write(formatted_json)
        sys.stdout.write("\n")

    except Exception as e:

        print(
            json.dumps(
                {
                    "error": str(e)
                },
                indent=4
            )
        )

        sys.exit(1)