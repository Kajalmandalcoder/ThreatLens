"""
ThreadLens - EML Parser

Responsibilities:
- Parse .eml files safely
- Extract email headers
- Analyze sender identity
- Extract plain-text and HTML bodies
- Analyze HTML structure
- Extract real HTTP/HTTPS URLs
- Support hxxp/hxxps and defanged URLs
- Ignore mailto/tel/sms/cid/data/javascript references
- Ignore local filenames such as .jpg/.png/.pdf
- Preserve structured link information
- Extract email journey / Received hops
- Extract attachments
- Base64-encode attachment contents for JSON transport
"""

# ============================================================
# STANDARD LIBRARY
# ============================================================

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

import base64
import json
import re
import sys
from html import unescape
from pathlib import Path
from urllib.parse import urlparse


# ============================================================
# PROJECT ROOT / IMPORT PATH
# ============================================================

CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# THIRD-PARTY IMPORTS
# ============================================================

from bs4 import BeautifulSoup

from url_intelligence.features import (
    extract_urls_from_text,
    normalize_raw_url,
    extract_registered_domain,
)


# ============================================================
# UTF-8 CONSOLE
# ============================================================

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass


# ============================================================
# CONSTANTS
# ============================================================

LOCAL_FILE_EXTENSIONS = {
    "jpg",
    "jpeg",
    "png",
    "gif",
    "webp",
    "svg",
    "bmp",
    "ico",
    "tif",
    "tiff",
    "css",
    "js",
    "map",
    "woff",
    "woff2",
    "ttf",
    "eot",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "txt",
    "csv",
    "zip",
    "rar",
    "7z",
}


NON_WEB_SCHEMES = {
    "mailto:",
    "tel:",
    "sms:",
    "cid:",
    "data:",
    "javascript:",
    "file:",
}


# ============================================================
# HELPER - NON WEB REFERENCE
# ============================================================

def is_non_web_reference(value):
    """
    Return True when a value is clearly not a web URL.
    """

    if not isinstance(value, str):
        return False

    text = value.strip().lower()

    return text.startswith(tuple(NON_WEB_SCHEMES))


# ============================================================
# HELPER - LOCAL FILENAME
# ============================================================

def is_local_filename(value):
    """
    Detect local filenames such as:

        image.jpg
        Cisco-ETR-Banner-4.jpg
        colous.png

    These must never become URLs.
    """

    if not isinstance(value, str):
        return False

    text = value.strip()

    if not text:
        return False

    # CID and local reference values
    if is_non_web_reference(text):
        return True

    # Do not block real URLs.
    if re.match(
        r"^(?:https?|hxxps?)://",
        text,
        flags=re.IGNORECASE,
    ):
        return False

    # Local filename pattern
    match = re.fullmatch(
        r"[A-Za-z0-9 _().\-]+\.([A-Za-z0-9]{2,10})",
        text,
    )

    if not match:
        return False

    extension = match.group(1).lower()

    return extension in LOCAL_FILE_EXTENSIONS


# ============================================================
# SENDER IDENTITY ANALYSIS
# ============================================================

def analyze_sender_identity(from_value):
    """
    Analyze sender display-name/domain consistency.

    This is an inconsistency signal only.
    It is NOT a final phishing verdict.
    """

    display_name, email_address = parseaddr(
        from_value or ""
    )

    display_name = display_name.strip()

    email_address = (
        email_address.strip().lower()
    )

    domain = ""

    if "@" in email_address:
        domain = (
            email_address
            .split("@", 1)[1]
            .strip()
            .lower()
        )

    mismatch = False
    reason = None

    known_brand_domains = {
        "microsoft": {
            "microsoft.com",
            "microsoftonline.com",
            "office.com",
            "live.com",
            "outlook.com",
        },
        "google": {
            "google.com",
            "googlemail.com",
        },
        "paypal": {
            "paypal.com",
        },
        "amazon": {
            "amazon.com",
            "amazon.in",
        },
        "apple": {
            "apple.com",
        },
        "linkedin": {
            "linkedin.com",
        },
        "github": {
            "github.com",
        },
        "cisco": {
            "cisco.com",
        },
    }

    normalized_name = re.sub(
        r"[^a-z0-9]",
        "",
        display_name.lower(),
    )

    for brand, domains in known_brand_domains.items():

        if brand in normalized_name:

            if domain not in domains:
                mismatch = True

                reason = (
                    f"Display name suggests {brand}, "
                    f"but sender domain is "
                    f"{domain or 'unknown'}"
                )

            break

    return {
        "displayName": (
            display_name
            or None
        ),
        "email": (
            email_address
            or None
        ),
        "domain": (
            domain
            or None
        ),
        "mismatch": mismatch,
        "reason": reason,
    }


# ============================================================
# EMAIL BODY STRUCTURAL ANALYSIS
# ============================================================

def analyze_body_structure(
    plain_text,
    html_text,
):
    """
    Analyze structural properties of email body.
    """

    plain_text = (
        plain_text
        if isinstance(plain_text, str)
        else ""
    )

    html_text = (
        html_text
        if isinstance(html_text, str)
        else ""
    )

    result = {
        "hasPlainText": bool(
            plain_text.strip()
        ),
        "hasHtml": bool(
            html_text.strip()
        ),
        "plainTextLength": len(
            plain_text
        ),
        "htmlLength": len(
            html_text
        ),
        "linkCount": 0,
        "externalLinkCount": 0,
        "imageCount": 0,
        "formCount": 0,
        "buttonCount": 0,
        "hiddenElementCount": 0,
        "scriptCount": 0,
        "iframeCount": 0,
    }

    if not html_text:
        return result

    soup = BeautifulSoup(
        html_text,
        "html.parser",
    )

    # ========================================================
    # ANCHOR LINKS
    # ========================================================

    anchor_links = soup.find_all(
        "a",
        href=True,
    )

    result["linkCount"] = len(
        anchor_links
    )

    external_links = 0

    for link in anchor_links:

        href = (
            link.get("href")
            or ""
        ).strip()

        href = unescape(href)

        if not href:
            continue

        if is_non_web_reference(href):
            continue

        if is_local_filename(href):
            continue

        normalized_href = normalize_raw_url(
            href
        )

        if not normalized_href:
            continue

        try:

            parsed = urlparse(
                normalized_href
            )

            hostname = (
                parsed.hostname
                or ""
            )

            if hostname:
                external_links += 1

        except Exception:
            pass

    result["externalLinkCount"] = (
        external_links
    )

    # ========================================================
    # IMAGES
    # ========================================================

    result["imageCount"] = len(
        soup.find_all("img")
    )

    # ========================================================
    # FORMS
    # ========================================================

    result["formCount"] = len(
        soup.find_all("form")
    )

    # ========================================================
    # BUTTONS
    # ========================================================

    button_count = 0

    button_count += len(
        soup.find_all("button")
    )

    button_count += len(
        soup.find_all(
            "input",
            attrs={
                "type": re.compile(
                    r"submit|button",
                    re.IGNORECASE,
                )
            },
        )
    )

    result["buttonCount"] = (
        button_count
    )

    # ========================================================
    # HIDDEN ELEMENTS
    # ========================================================

    hidden_count = 0

    for element in soup.find_all():

        style = (
            element.get("style")
            or ""
        ).lower()

        classes = " ".join(
            element.get(
                "class",
                [],
            )
        ).lower()

        element_type = (
            element.get("type")
            or ""
        ).lower()

        normalized_style = re.sub(
            r"\s+",
            "",
            style,
        )

        if (
            "display:none" in normalized_style
            or
            "visibility:hidden" in normalized_style
            or
            element.has_attr("hidden")
            or
            "hidden" in classes
            or
            element_type == "hidden"
        ):
            hidden_count += 1

    result["hiddenElementCount"] = (
        hidden_count
    )

    # ========================================================
    # SCRIPT
    # ========================================================

    result["scriptCount"] = len(
        soup.find_all("script")
    )

    # ========================================================
    # IFRAME
    # ========================================================

    result["iframeCount"] = len(
        soup.find_all("iframe")
    )

    return result


# ============================================================
# EMAIL JOURNEY
# ============================================================

def parse_email_journey(received_headers):
    """
    Parse Received headers into an email journey.
    Only explicitly visible IP values are extracted.
    """

    journey = []

    if not isinstance(
        received_headers,
        (list, tuple),
    ):
        received_headers = []

    for index, received in enumerate(
        received_headers,
        start=1,
    ):

        if not isinstance(
            received,
            str,
        ):
            received = str(received)

        hop = {
            "hop_id": index,
            "from": None,
            "by": None,
            "ip": None,
            "timestamp": None,
        }

        # ====================================================
        # FROM SERVER
        # ====================================================

        from_match = re.search(
            r"\bfrom\s+([^\s(]+)",
            received,
            re.IGNORECASE,
        )

        if from_match:

            from_server = (
                from_match.group(1)
            )

            if not re.fullmatch(
                r"[0-9a-fA-F:.]+",
                from_server,
            ):
                hop["from"] = from_server

        # ====================================================
        # BY SERVER
        # ====================================================

        by_match = re.search(
            r"\bby\s+([^\s;]+)",
            received,
            re.IGNORECASE,
        )

        if by_match:

            by_server = (
                by_match.group(1)
            )

            if not re.fullmatch(
                r"[0-9a-fA-F:.]+",
                by_server,
            ):
                hop["by"] = by_server

        # ====================================================
        # EXPLICIT IP INSIDE [ ]
        # ====================================================

        ip_matches = re.findall(
            r"\[([0-9a-fA-F:.]+)\]",
            received,
        )

        if ip_matches:

            # Prefer a public-looking IP where possible.
            hop["ip"] = ip_matches[0]

        # ====================================================
        # FALLBACK IP FROM FROM SERVER
        # ====================================================

        if hop["ip"] is None and from_match:

            candidate = (
                from_match.group(1)
            )

            if re.fullmatch(
                r"[0-9a-fA-F:.]+",
                candidate,
            ):
                hop["ip"] = candidate

        # ====================================================
        # FALLBACK IP FROM BY SERVER
        # ====================================================

        if hop["ip"] is None and by_match:

            candidate = (
                by_match.group(1)
            )

            if re.fullmatch(
                r"[0-9a-fA-F:.]+",
                candidate,
            ):
                hop["ip"] = candidate

        # ====================================================
        # TIMESTAMP
        # ====================================================

        timestamp_match = re.search(
            r"([A-Z][a-z]{2},\s+"
            r"\d{1,2}\s+"
            r"[A-Z][a-z]{2}\s+"
            r"\d{4}\s+"
            r"\d{2}:\d{2}:\d{2}\s+"
            r"[+-]\d{4})",
            received,
        )

        if timestamp_match:

            hop["timestamp"] = (
                timestamp_match.group(1)
            )

        journey.append(hop)

    return journey


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_email_urls(
    plain_text,
    html_text,
):
    """
    Extract only actual web URLs.

    Supports:
    - http://
    - https://
    - hxxp://
    - hxxps://
    - defanged URLs
    - href/src/action/data-* attributes

    Ignores:
    - mailto:
    - tel:
    - sms:
    - cid:
    - data:
    - javascript:
    - local image/file names
    - domains embedded inside email addresses

    Also de-duplicates HTML entity variants.
    """

    canonical_urls = {}

    # ========================================================
    # ADD URL
    # ========================================================

    def add_url(value):

        if not value:
            return

        if not isinstance(value, str):
            return

        # Decode HTML entities:
        # &amp; -> &
        # &quot; -> "
        value = unescape(
            value
        ).strip()

        if not value:
            return

        # ----------------------------------------------------
        # NON-WEB
        # ----------------------------------------------------

        if is_non_web_reference(
            value
        ):
            return

        # ----------------------------------------------------
        # LOCAL FILE
        # ----------------------------------------------------

        if is_local_filename(value):
            return

        # ----------------------------------------------------
        # EMAIL ADDRESS
        # ----------------------------------------------------

        # A value like:
        # india_ur_communications@cisco.com
        # is NOT a URL.

        if (
            "@" in value
            and not re.match(
                r"^(?:https?|hxxps?)://",
                value,
                flags=re.IGNORECASE,
            )
        ):
            return

        # ----------------------------------------------------
        # NORMALIZE
        # ----------------------------------------------------

        normalized = normalize_raw_url(
            value
        )

        if not normalized:
            return

        normalized = unescape(
            normalized
        ).strip()

        if not normalized:
            return

        # ----------------------------------------------------
        # PARSE
        # ----------------------------------------------------

        comparison_url = normalized

        has_scheme = bool(
            re.match(
                r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
                comparison_url,
            )
        )

        if not has_scheme:

            comparison_url = (
                "http://"
                + comparison_url
            )

        try:

            parsed = urlparse(
                comparison_url
            )

        except Exception:
            return

        hostname = (
            parsed.hostname
            or ""
        ).lower()

        # No hostname = not a usable web URL.
        if not hostname:
            return

        # ----------------------------------------------------
        # LOCAL FILE HOSTNAME
        # ----------------------------------------------------

        if not has_scheme:

            hostname_extension = ""

            if "." in hostname:
                hostname_extension = (
                    hostname
                    .rsplit(".", 1)[-1]
                    .lower()
                )

            if (
                hostname_extension
                in LOCAL_FILE_EXTENSIONS
            ):
                return

        # ----------------------------------------------------
        # CANONICAL FORM
        # ----------------------------------------------------

        canonical_key = (
            comparison_url
            .lower()
        )

        canonical_key = unescape(
            canonical_key
        )

        # ----------------------------------------------------
        # HTTPS PREFERENCE
        # ----------------------------------------------------

        if canonical_key.startswith(
            "http://"
        ):

            https_key = (
                "https://"
                + canonical_key[
                    len("http://"):
                ]
            )

            if https_key in canonical_urls:
                return

        elif canonical_key.startswith(
            "https://"
        ):

            http_key = (
                "http://"
                + canonical_key[
                    len("https://"):
                ]
            )

            canonical_urls.pop(
                http_key,
                None,
            )

        # ----------------------------------------------------
        # SAVE
        # ----------------------------------------------------

        if canonical_key not in canonical_urls:
            canonical_urls[
                canonical_key
            ] = normalized

    # ========================================================
    # PLAIN TEXT
    # ========================================================

    for url in extract_urls_from_text(
        plain_text
    ):

        candidate = unescape(
            url
        ).strip()

        if not candidate:
            continue

        if is_non_web_reference(
            candidate
        ):
            continue

        if is_local_filename(
            candidate
        ):
            continue

        add_url(candidate)

    # ========================================================
    # HTML
    # ========================================================

    if html_text:

        decoded_html = unescape(
            html_text
        )

        soup = BeautifulSoup(
            decoded_html,
            "html.parser",
        )

        url_attributes = (
            "href",
            "src",
            "action",
            "formaction",
            "cite",
            "data-url",
            "data-href",
            "data-link",
        )

        # ----------------------------------------------------
        # ACTUAL HTML URL ATTRIBUTES
        # ----------------------------------------------------

        for element in soup.find_all():

            for attribute_name in url_attributes:

                value = element.get(
                    attribute_name
                )

                if not value:
                    continue

                value = unescape(
                    str(value)
                ).strip()

                if not value:
                    continue

                if is_non_web_reference(
                    value
                ):
                    continue

                if is_local_filename(
                    value
                ):
                    continue

                # Whole attribute
                add_url(value)

                # Embedded URLs
                for extracted_url in (
                    extract_urls_from_text(
                        value
                    )
                ):

                    add_url(
                        extracted_url
                    )

        # ----------------------------------------------------
        # RAW HTML URL SCAN
        # ----------------------------------------------------

        for extracted_url in (
            extract_urls_from_text(
                decoded_html
            )
        ):

            candidate = unescape(
                extracted_url
            ).strip()

            if not candidate:
                continue

            if is_non_web_reference(
                candidate
            ):
                continue

            if is_local_filename(
                candidate
            ):
                continue

            # ------------------------------------------------
            # IMPORTANT:
            # Prevent domain inside an email address
            #
            # Example:
            # india_ur_communications@cisco.com
            #
            # The feature extractor may return:
            # cisco.com
            #
            # That must NOT become:
            # http://cisco.com
            # ------------------------------------------------

            if not re.match(
                r"^(?:https?|hxxps?)://",
                candidate,
                flags=re.IGNORECASE,
            ):

                email_domain_pattern = (
                    rf"@[^\s<>'\"]*"
                    rf"{re.escape(candidate)}"
                )

                if re.search(
                    email_domain_pattern,
                    decoded_html,
                    flags=re.IGNORECASE,
                ):
                    continue

            add_url(candidate)

    return sorted(
        canonical_urls.values(),
        key=lambda value: value.lower(),
    )


# ============================================================
# STRUCTURED LINKS
# ============================================================

def build_structured_links(urls):
    """
    Convert URLs into structured link objects.
    """

    links = []

    for url in urls:

        try:

            normalized = normalize_raw_url(
                url
            )

            if not normalized:
                continue

            normalized = unescape(
                normalized
            ).strip()

            if is_non_web_reference(
                normalized
            ):
                continue

            if is_local_filename(
                normalized
            ):
                continue

            parsed = urlparse(
                normalized
            )

            hostname = (
                parsed.hostname
                or ""
            ).lower()

            if not hostname:
                continue

            registered_domain = (
                extract_registered_domain(
                    hostname
                )
            )

            links.append({
                "url": normalized,
                "domain": (
                    registered_domain
                    or hostname
                ),
                "scheme": (
                    parsed.scheme
                    or None
                ),
                "path": (
                    parsed.path
                    or ""
                ),
                "query": (
                    parsed.query
                    or ""
                ),
                "fragment": (
                    parsed.fragment
                    or ""
                ),
            })

        except Exception:

            continue

    return links


# ============================================================
# ATTACHMENT EXTRACTION
# ============================================================

def extract_attachments(msg):
    """
    Extract MIME attachments.

    Binary payload is Base64 encoded
    for JSON transport.
    """

    attachments = []

    for part in msg.walk():

        filename = part.get_filename()

        if not filename:
            continue

        try:

            payload = (
                part.get_payload(
                    decode=True
                )
            )

        except Exception:

            payload = None

        if payload is None:
            payload = b""

        try:

            encoded_content = (
                base64.b64encode(
                    payload
                ).decode("utf-8")
            )

        except Exception:

            encoded_content = ""

        attachments.append({
            "filename": filename,
            "contentType": (
                part.get_content_type()
            ),
            "size": len(payload),
            "content": encoded_content,
        })

    return attachments


# ============================================================
# EMAIL PARSER
# ============================================================

def parse_email(file_path):
    """
    Parse a complete EML file.
    """

    file_path = Path(
        file_path
    )

    if not file_path.exists():

        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    # ========================================================
    # READ EML
    # ========================================================

    with open(
        file_path,
        "rb",
    ) as file:

        msg = BytesParser(
            policy=policy.default
        ).parse(file)

    # ========================================================
    # BASIC HEADERS
    # ========================================================

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
        "received": msg.get_all(
            "Received",
            [],
        ),
    }

    # ========================================================
    # SENDER IDENTITY
    # ========================================================

    sender_identity = (
        analyze_sender_identity(
            headers["from"]
        )
    )

    # ========================================================
    # EMAIL JOURNEY
    # ========================================================

    email_journey = {
        "hops": parse_email_journey(
            headers["received"]
        )
    }

    # ========================================================
    # BODY
    # ========================================================

    plain_text = ""
    html_text = ""

    for part in msg.walk():

        content_type = (
            part.get_content_type()
        )

        if content_type == "text/plain":

            try:

                content = (
                    part.get_content()
                )

                if isinstance(
                    content,
                    str,
                ):
                    plain_text += content

            except Exception:
                pass

        elif content_type == "text/html":

            try:

                content = (
                    part.get_content()
                )

                if isinstance(
                    content,
                    str,
                ):
                    html_text += content

            except Exception:
                pass

    # ========================================================
    # BODY STRUCTURE
    # ========================================================

    body_structure = (
        analyze_body_structure(
            plain_text,
            html_text,
        )
    )

    # ========================================================
    # URL EXTRACTION
    # ========================================================

    urls = extract_email_urls(
        plain_text,
        html_text,
    )

    links = build_structured_links(
        urls
    )

    body_structure[
        "detectedUrlCount"
    ] = len(urls)

    # ========================================================
    # ATTACHMENTS
    # ========================================================

    attachments = (
        extract_attachments(msg)
    )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    result = {
        "headers": headers,

        "senderIdentity":
            sender_identity,

        "body": {
            "plainText":
                plain_text,
            "html":
                html_text,
        },

        "bodyStructure":
            body_structure,

        "links":
            links,

        "attachments":
            attachments,

        "emailJourney":
            email_journey,
    }

    return result


# ============================================================
# COMMAND LINE ENTRY POINT
# ============================================================

def main():
    if len(sys.argv) < 2:

        print(
            json.dumps(
                {
                    "error":
                        "No .eml file provided"
                },
                ensure_ascii=False,
                indent=4,
            )
        )

        return 1

    file_path = Path(
        sys.argv[1]
    )

    if not file_path.exists():

        print(
            json.dumps(
                {
                    "error":
                        f"File not found: {file_path}"
                },
                ensure_ascii=False,
                indent=4,
            )
        )

        return 1

    try:

        result = parse_email(
            file_path
        )

        formatted_json = json.dumps(
            result,
            ensure_ascii=False,
            indent=4,
        )

        sys.stdout.write(
            formatted_json
        )

        sys.stdout.write(
            "\n"
        )

        return 0

    except Exception as exc:

        print(
            json.dumps(
                {
                    "error":
                        str(exc)
                },
                ensure_ascii=False,
                indent=4,
            )
        )

        return 1


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    raise SystemExit(
        main()
    )