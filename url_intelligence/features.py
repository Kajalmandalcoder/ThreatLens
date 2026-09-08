"""
ThreadLens - URL Intelligence Feature Extraction

Responsibilities:
- Normalize normal and defanged URLs
- Extract URLs from email text
- Parse URL components safely
- Detect URL structural indicators
- Detect suspicious fragments and tracking paths
- Detect suspicious keywords
- Detect URL shorteners
- Detect punycode / IP hosts
- Detect sender-domain mismatch
- Detect suspicious TLDs
- Ignore non-web references such as mailto:

No network requests are performed here.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse

import tldextract


# ============================================================
# KNOWN URL SHORTENERS
# ============================================================

KNOWN_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "bit.do",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "tiny.cc",
    "rebrand.ly",
    "lnkd.in",
    "s.id",
    "soo.gd",
}


# ============================================================
# SUSPICIOUS KEYWORDS
# ============================================================

SUSPICIOUS_PATH_KEYWORDS = {
    "login",
    "log-in",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "authenticate",
    "authentication",
    "account",
    "password",
    "credential",
    "credentials",
    "banking",
    "payment",
    "billing",
    "secure",
    "security",
    "update",
    "confirm",
    "confirmation",
    "wallet",
    "recover",
    "recovery",
    "unlock",
    "suspend",
    "suspended",
    "invoice",
    "otp",
    "mfa",
    "2fa",
    "reset",
    "validate",
    "authorization",
    "authorize",
}


# ============================================================
# SUSPICIOUS TLDs
# ============================================================

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "shop",
    "support",
    "live",
    "buzz",
    "icu",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
    "work",
    "fit",
    "zip",
    "mov",
}


# ============================================================
# NON-WEB SCHEMES
# ============================================================

NON_WEB_SCHEMES = {
    "mailto",
    "tel",
    "sms",
    "cid",
    "data",
    "javascript",
}


# ============================================================
# TRUSTED EXTERNAL DOMAINS
#
# External does NOT automatically mean malicious.
# ============================================================

TRUSTED_EXTERNAL_DOMAINS = {
    "google.com",
    "google.co.in",
    "googleusercontent.com",
    "googleapis.com",
    "gstatic.com",
    "linkedin.com",
    "licdn.com",
    "microsoft.com",
    "apple.com",
    "itunes.com",
    "w3.org",
    "icons8.com",
    "t.me",
    "telegram.org",
    "upbit.com",
}


# ============================================================
# TRUSTED ASSET / CDN DOMAINS
# ============================================================

TRUSTED_ASSET_DOMAINS = {
    "linkedin.com",
    "licdn.com",
    "google.com",
    "googleapis.com",
    "googleusercontent.com",
    "gstatic.com",
    "microsoft.com",
    "microsoftonline.com",
    "apple.com",
    "icloud.com",
    "icons8.com",
}


# ============================================================
# DEFANGED URL PATTERNS
# ============================================================

DEFANGED_PATTERNS = (
    re.compile(r"\bhxxps?://", re.IGNORECASE),
    re.compile(r"\[\s*\.\s*\]", re.IGNORECASE),
    re.compile(r"\(\s*\.\s*\)", re.IGNORECASE),
    re.compile(r"\{\s*\.\s*\}", re.IGNORECASE),
    re.compile(r"\[\s*dot\s*\]", re.IGNORECASE),
    re.compile(r"\(\s*dot\s*\)", re.IGNORECASE),
    re.compile(r"\{\s*dot\s*\}", re.IGNORECASE),
    re.compile(r"\[\s*at\s*\]", re.IGNORECASE),
    re.compile(r"\(\s*at\s*\)", re.IGNORECASE),
    re.compile(r"\{\s*at\s*\}", re.IGNORECASE),
)


# ============================================================
# HELPERS
# ============================================================

def is_non_web_reference(value: Any) -> bool:
    """
    Return True for references which should not be treated
    as normal HTTP/HTTPS URLs.
    """
    if not isinstance(value, str):
        return False

    text = value.strip().lower()

    for scheme in NON_WEB_SCHEMES:
        if text.startswith(f"{scheme}:"):
            return True

    return False


def _is_trusted_external_domain(
    registered_domain: Optional[str],
) -> bool:
    if not registered_domain:
        return False

    return registered_domain.lower() in TRUSTED_EXTERNAL_DOMAINS


def _is_trusted_asset_domain(
    registered_domain: Optional[str],
) -> bool:
    if not registered_domain:
        return False

    return registered_domain.lower() in TRUSTED_ASSET_DOMAINS


# ============================================================
# DEFANGED DETECTION
# ============================================================

def is_defanged_url(value: Any) -> bool:
    """
    Detect common security-sample URL defanging.
    """
    if not isinstance(value, str):
        return False

    text = value.strip()

    if not text:
        return False

    return any(
        pattern.search(text)
        for pattern in DEFANGED_PATTERNS
    )


# ============================================================
# DEFANGED NORMALIZATION
# ============================================================

def normalize_defanged_url(
    value: Any,
) -> Optional[str]:
    """
    Convert common defanged URL notation into normal notation.
    """

    if value is None:
        return None

    if not isinstance(value, str):
        return None

    text = value.strip()

    if not text:
        return None

    # Keep non-web schemes untouched.
    if is_non_web_reference(text):
        return text

    # --------------------------------------------------------
    # Scheme
    # --------------------------------------------------------

    text = re.sub(
        r"^hxxps://",
        "https://",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r"^hxxp://",
        "http://",
        text,
        flags=re.IGNORECASE,
    )

    # --------------------------------------------------------
    # Defanged dots and @
    # --------------------------------------------------------

    replacements = (
        (r"\[\s*\.\s*\]", "."),
        (r"\(\s*\.\s*\)", "."),
        (r"\{\s*\.\s*\}", "."),
        (r"\[\s*dot\s*\]", "."),
        (r"\(\s*dot\s*\)", "."),
        (r"\{\s*dot\s*\}", "."),
        (r"\[\s*at\s*\]", "@"),
        (r"\(\s*at\s*\)", "@"),
        (r"\{\s*at\s*\}", "@"),
    )

    for pattern, replacement in replacements:
        text = re.sub(
            pattern,
            replacement,
            text,
            flags=re.IGNORECASE,
        )

    # Remove wrapping angle brackets.
    if (
        len(text) >= 2
        and text.startswith("<")
        and text.endswith(">")
    ):
        text = text[1:-1].strip()

    return text or None


# ============================================================
# RAW URL NORMALIZATION
# ============================================================

def normalize_raw_url(
    raw_input: Any,
) -> Optional[str]:
    """
    Accept:
    - string
    - dict containing url/href/link
    """

    if raw_input is None:
        return None

    if isinstance(raw_input, dict):
        raw_input = (
            raw_input.get("url")
            or raw_input.get("href")
            or raw_input.get("link")
            or ""
        )

    if not isinstance(raw_input, str):
        return None

    cleaned = raw_input.strip()

    if not cleaned:
        return None

    return normalize_defanged_url(cleaned)


# ============================================================
# URL EXTRACTION FROM TEXT
# ============================================================

def extract_urls_from_text(
    text: Optional[str],
) -> List[str]:
    """
    Extract:
    - HTTP/HTTPS URLs
    - HXXP/HXXPS URLs
    - Defanged domains
    - Plain domains

    Non-web schemes such as mailto:/tel:/sms: are ignored.
    """

    if not text or not isinstance(text, str):
        return []

    found: List[str] = []

    # --------------------------------------------------------
    # Normal / defanged scheme URLs
    # --------------------------------------------------------

    scheme_pattern = re.compile(
        r"""
        (?:
            https?://
            |
            hxxps?://
        )
        [^\s<>"']+
        """,
        flags=re.IGNORECASE | re.VERBOSE,
    )

    for match in scheme_pattern.finditer(text):
        candidate = match.group(0)

        candidate = candidate.rstrip(
            ".,;:!?)]}>"
        )

        if candidate:
            found.append(candidate)

    # --------------------------------------------------------
    # Defanged domains
    #
    # Examples:
    #   example[.]com
    #   example[.]com/path
    #   example[dot]com
    # --------------------------------------------------------

    defanged_domain_pattern = re.compile(
        r"""
        \b
        [a-zA-Z0-9-]+
        (?:
            \s*
            (?:
                \[\s*\.\s*\]
                |
                \(\s*\.\s*\)
                |
                \{\s*\.\s*\}
                |
                \[\s*dot\s*\]
                |
                \(\s*dot\s*\)
                |
                \{\s*dot\s*\}
            )
            \s*
            [a-zA-Z0-9-]+
        )+
        \.[a-zA-Z]{2,}
        (?:
            [/?#]
            [^\s<>"']*
        )?
        """,
        flags=re.IGNORECASE | re.VERBOSE,
    )

    for match in defanged_domain_pattern.finditer(text):
        candidate = match.group(0).strip()

        candidate = candidate.rstrip(
            ".,;:!?)]}>"
        )

        if candidate:
            found.append(candidate)

    # --------------------------------------------------------
    # Plain domains
    # --------------------------------------------------------

    plain_domain_pattern = re.compile(
        r"""
        \b
        (?:
            https?://
        )?
        (?:[a-zA-Z0-9-]+\.)+
        [a-zA-Z]{2,}
        (?:
            /[^\s<>"']*
        )?
        """,
        flags=re.IGNORECASE | re.VERBOSE,
    )

    for match in plain_domain_pattern.finditer(text):
        candidate = match.group(0).strip()

        if "." not in candidate:
            continue

        candidate = candidate.rstrip(
            ".,;:!?)]}>"
        )

        lower_candidate = candidate.lower()

        # Prevent mail addresses / non-web references
        # from being counted as HTTP URLs.
        if (
            lower_candidate.startswith(
                (
                    "mailto:",
                    "tel:",
                    "sms:",
                    "cid:",
                    "data:",
                    "javascript:",
                )
            )
        ):
            continue

        # If the candidate is actually the domain portion
        # of an email address, skip it.
        if "@" in candidate:
            continue

        if candidate:
            found.append(candidate)

    # --------------------------------------------------------
    # Normalize + deduplicate
    # --------------------------------------------------------

    unique_urls: List[str] = []
    seen = set()

    for candidate in found:

        normalized = normalize_raw_url(candidate)

        if not normalized:
            continue

        if is_non_web_reference(normalized):
            continue

        key = normalized.lower()

        if key in seen:
            continue

        seen.add(key)
        unique_urls.append(normalized)

    return unique_urls


# ============================================================
# REGISTERED DOMAIN
# ============================================================

def extract_registered_domain(
    hostname: Optional[str],
) -> Optional[str]:
    """
    Extract registered/root domain.

    Examples:
        www.example.com -> example.com
        mail.linkedin.com -> linkedin.com
    """

    if not hostname:
        return None

    try:
        extracted = tldextract.extract(hostname)

        registered = (
            getattr(
                extracted,
                "top_domain_under_public_suffix",
                None,
            )
            or getattr(
                extracted,
                "registered_domain",
                None,
            )
        )

        if registered:
            return registered.lower()

    except Exception:
        pass

    return None


# ============================================================
# URL COMPONENTS
# ============================================================

def extract_url_components(
    url: str,
) -> Dict[str, Any]:

    try:
        if not isinstance(url, str):
            raise ValueError("URL must be a string")

        original_url = url.strip()

        if not original_url:
            raise ValueError("Empty URL")

        # ----------------------------------------------------
        # Non-web reference
        # ----------------------------------------------------

        if is_non_web_reference(original_url):

            return {
                "scheme": (
                    original_url.split(
                        ":",
                        1,
                    )[0].lower()
                ),
                "hostname": "",
                "registered_domain": None,
                "port": None,
                "path": "",
                "query": "",
                "fragment": "",
                "username": None,
                "password": None,
                "is_valid": True,
                "is_non_web_reference": True,
                "had_original_scheme": True,
                "was_defanged": False,
                "original_url": original_url,
                "normalized_url": original_url,
            }

        # ----------------------------------------------------
        # Normalize
        # ----------------------------------------------------

        normalized_url = normalize_defanged_url(
            original_url
        )

        if not normalized_url:
            raise ValueError(
                "Unable to normalize URL"
            )

        original_had_scheme = bool(
            re.match(
                r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
                original_url,
            )
        )

        normalized_has_scheme = bool(
            re.match(
                r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
                normalized_url,
            )
        )

        parse_target = normalized_url

        if not normalized_has_scheme:
            parse_target = (
                "http://"
                + normalized_url
            )

        parsed = urlparse(parse_target)

        hostname = (
            parsed.hostname
            or ""
        ).strip().lower()

        if not hostname:

            return {
                "scheme": "invalid",
                "hostname": "",
                "registered_domain": None,
                "port": None,
                "path": "",
                "query": "",
                "fragment": "",
                "username": None,
                "password": None,
                "is_valid": False,
                "is_non_web_reference": False,
                "had_original_scheme":
                    original_had_scheme,
                "was_defanged":
                    is_defanged_url(
                        original_url
                    ),
                "original_url":
                    original_url,
                "normalized_url":
                    normalized_url,
                "error":
                    "Missing hostname",
            }

        registered_domain = (
            extract_registered_domain(
                hostname
            )
        )

        try:
            port = parsed.port
        except ValueError:
            port = None

        return {
            "scheme": (
                parsed.scheme.lower()
                if parsed.scheme
                else "unknown"
            ),
            "hostname": hostname,
            "registered_domain":
                registered_domain,
            "port": port,
            "path":
                parsed.path or "",
            "query":
                parsed.query or "",
            "fragment":
                parsed.fragment or "",
            "username":
                parsed.username,
            "password":
                parsed.password,
            "is_valid":
                True,
            "is_non_web_reference":
                False,
            "had_original_scheme":
                original_had_scheme,
            "was_defanged":
                is_defanged_url(
                    original_url
                ),
            "original_url":
                original_url,
            "normalized_url":
                normalized_url,
        }

    except Exception as exc:

        return {
            "scheme": "invalid",
            "hostname": "",
            "registered_domain": None,
            "port": None,
            "path": "",
            "query": "",
            "fragment": "",
            "username": None,
            "password": None,
            "is_valid": False,
            "is_non_web_reference": False,
            "had_original_scheme": False,
            "was_defanged":
                is_defanged_url(url),
            "original_url": url,
            "normalized_url": None,
            "error": str(exc),
        }


# ============================================================
# SENDER ROOT DOMAIN
# ============================================================

def extract_sender_root_domain(
    sender_email: Optional[str],
) -> Optional[str]:

    if (
        not sender_email
        or not isinstance(
            sender_email,
            str,
        )
        or "@"
        not in sender_email
    ):
        return None

    try:

        domain_part = (
            sender_email
            .split("@", 1)[1]
            .strip()
            .strip("<>")
            .lower()
        )

        return extract_registered_domain(
            domain_part
        )

    except Exception:
        return None


# ============================================================
# SUBDOMAIN COUNT
# ============================================================

def calculate_subdomain_count(
    hostname: Optional[str],
    registered_domain: Optional[str],
) -> int:

    if (
        not hostname
        or not registered_domain
    ):
        return 0

    try:

        hostname_labels = [
            label
            for label
            in hostname.split(".")
            if label
        ]

        root_labels = [
            label
            for label
            in registered_domain.split(".")
            if label
        ]

        return max(
            len(hostname_labels)
            - len(root_labels),
            0,
        )

    except Exception:
        return 0


# ============================================================
# SUSPICIOUS KEYWORDS
# ============================================================

def find_suspicious_keywords(
    path: str,
    query: str,
    fragment: str,
) -> List[str]:

    decoded_path = unquote(
        path or ""
    ).lower()

    decoded_query = unquote(
        query or ""
    ).lower()

    decoded_fragment = unquote(
        fragment or ""
    ).lower()

    searchable = (
        f"{decoded_path}?"
        f"{decoded_query}#"
        f"{decoded_fragment}"
    )

    matches: List[str] = []

    for keyword in sorted(
        SUSPICIOUS_PATH_KEYWORDS
    ):

        pattern = (
            rf"(?<![a-zA-Z0-9])"
            rf"{re.escape(keyword)}"
            rf"(?![a-zA-Z0-9])"
        )

        if re.search(
            pattern,
            searchable,
        ):
            matches.append(keyword)

    return matches


# ============================================================
# LONG URL DETECTION
# ============================================================

def _detect_unusually_long_url(
    raw_url: str,
    registered_domain: Optional[str],
    query: str,
    fragment: str,
) -> bool:
    """
    Reduce false positives for legitimate platform/CDN URLs.
    """

    length = len(raw_url)

    if length <= 180:
        return False

    if _is_trusted_external_domain(
        registered_domain
    ):
        if length <= 650:
            return False

    decoded_query = unquote(
        query or ""
    ).lower()

    decoded_fragment = unquote(
        fragment or ""
    ).lower()

    suspicious_parameter_pattern = re.compile(
        r"""
        (?:
            redirect
            |
            destination
            |
            target
            |
            continue
            |
            next
            |
            return
            |
            url=
            |
            token=
            |
            auth=
            |
            login=
            |
            verify=
        )
        """,
        flags=re.IGNORECASE | re.VERBOSE,
    )

    suspicious_query = bool(
        suspicious_parameter_pattern.search(
            decoded_query
        )
    )

    suspicious_fragment = bool(
        suspicious_parameter_pattern.search(
            decoded_fragment
        )
    )

    if length > 300:
        return True

    return (
        length > 180
        and (
            suspicious_query
            or suspicious_fragment
        )
    )


# ============================================================
# OBFUSCATED PATH
# ============================================================

def _detect_obfuscated_path(
    path: str,
    registered_domain: Optional[str],
) -> bool:
    """
    Detect meaningful path obfuscation while avoiding
    false positives from legitimate CDN/platform IDs.
    """

    if not path:
        return False

    # Trusted asset platforms commonly use generated IDs.
    if _is_trusted_asset_domain(
        registered_domain
    ):
        return bool(
            re.search(
                r"(?:%[0-9a-fA-F]{2}){3,}",
                path,
            )
        )

    # Repeated percent encoding.
    if re.search(
        r"(?:%[0-9a-fA-F]{2}){3,}",
        path,
    ):
        return True

    decoded_path = unquote(path)

    segments = [
        segment
        for segment in decoded_path.split("/")
        if segment
    ]

    for segment in segments:

        compact = re.sub(
            r"[-_.]",
            "",
            segment,
        )

        if (
            len(compact) >= 32
            and re.fullmatch(
                r"[A-Za-z0-9]+",
                compact,
            )
        ):
            return True

    return False


# ============================================================
# SUSPICIOUS FRAGMENT
# ============================================================

def _detect_suspicious_fragment(
    fragment: str,
) -> bool:
    """
    Detect redirect/tracking/token-like fragment structures.

    Normal:
        #section1

    Suspicious:
        #index.php?search=...
    """

    decoded_fragment = unquote(
        fragment or ""
    ).lower()

    if not decoded_fragment:
        return False

    patterns = (
        r"(?:^|[?&])search=",
        r"(?:^|[?&])page=",
        r"(?:^|[?&])next=",
        r"(?:^|[?&])url=",
        r"(?:^|[?&])target=",
        r"(?:^|[?&])destination=",
        r"(?:^|[?&])redirect=",
        r"(?:^|[?&])token=",
        r"(?:^|[?&])continue=",
        r"(?:^|[?&])session=",
        r"(^|/)redirect(/|$)",
        r"(^|/)tracking(/|$)",
        r"(^|/)track(/|$)",
    )

    for pattern in patterns:

        if re.search(
            pattern,
            decoded_fragment,
            flags=re.IGNORECASE,
        ):
            return True

    # index.php alone is NOT suspicious.
    if re.search(
        r"index\.php",
        decoded_fragment,
        flags=re.IGNORECASE,
    ):
        return bool(
            re.search(
                r"[?&]"
                r"(?:search|page|next|url|target|"
                r"destination|redirect|token|continue)=",
                decoded_fragment,
                flags=re.IGNORECASE,
            )
        )

    return False


# ============================================================
# TRACKING PATH
# ============================================================

def _detect_tracking_path(
    path: str,
    registered_domain: Optional[str],
) -> bool:
    """
    Detect explicit tracking / redirect path segments.
    """

    decoded_path = unquote(
        path or ""
    ).lower()

    if not decoded_path:
        return False

    segments = {
        segment
        for segment
        in decoded_path.split("/")
        if segment
    }

    tracking_segments = {
        "track",
        "tracking",
        "redirect",
        "redirects",
        "click",
        "clicks",
        "bounce",
        "pixel",
        "tracker",
    }

    return bool(
        segments.intersection(
            tracking_segments
        )
    )


# ============================================================
# STATIC FEATURES
# ============================================================

def extract_static_features(
    components: Dict[str, Any],
    raw_url: str,
    sender_root_domain: Optional[str] = None,
    original_url: Optional[str] = None,
) -> Dict[str, Any]:

    hostname = (
        components.get("hostname")
        or ""
    )

    scheme = (
        components.get("scheme")
        or ""
    ).lower()

    path = (
        components.get("path")
        or ""
    )

    query = (
        components.get("query")
        or ""
    )

    fragment = (
        components.get("fragment")
        or ""
    )

    registered_domain = (
        components.get(
            "registered_domain"
        )
    )

    evidence_url = (
        original_url
        if isinstance(
            original_url,
            str,
        )
        and original_url.strip()
        else raw_url
    )

    is_non_web = (
        components.get(
            "is_non_web_reference",
            False,
        )
        is True
    )

    # ========================================================
    # NON-WEB
    # ========================================================

    if is_non_web:

        return {
            "url_length": len(raw_url),
            "is_http_only": False,
            "is_https": False,
            "is_defanged": False,
            "is_ip_hostname": False,
            "ip_version": None,
            "is_shortener": False,
            "subdomain_count": 0,
            "has_excessive_subdomains": False,
            "is_unusually_long": False,
            "has_at_symbol": False,
            "has_username": False,
            "has_password": False,
            "has_hex_encoding": False,
            "has_suspicious_chars": False,
            "is_punycode": False,
            "matched_keywords": [],
            "has_suspicious_fragment": False,
            "has_tracking_path": False,
            "has_obfuscated_path": False,
            "is_sender_mismatch": False,
            "is_trusted_external": False,
            "suspicious_tld": False,
            "tld": None,
            "is_non_web_reference": True,
        }

    # ========================================================
    # SCHEME
    # ========================================================

    is_http_only = (
        scheme == "http"
    )

    is_https = (
        scheme == "https"
    )

    # ========================================================
    # DEFANGED
    # ========================================================

    is_defanged = (
        components.get(
            "was_defanged"
        )
        is True
        or is_defanged_url(
            evidence_url
        )
    )

    # ========================================================
    # IP HOSTNAME
    # ========================================================

    is_ip_hostname = False
    ip_version = None

    if hostname:

        try:

            ip_obj = ipaddress.ip_address(
                hostname
            )

            is_ip_hostname = True
            ip_version = ip_obj.version

        except ValueError:
            pass

    # ========================================================
    # SHORTENER
    # ========================================================

    is_shortener = (
        registered_domain
        in KNOWN_SHORTENERS
    )

    # ========================================================
    # SUBDOMAINS
    # ========================================================

    subdomain_count = (
        calculate_subdomain_count(
            hostname,
            registered_domain,
        )
    )

    has_excessive_subdomains = (
        subdomain_count >= 3
    )

    # ========================================================
    # LENGTH
    # ========================================================

    url_length = len(raw_url)

    is_unusually_long = (
        _detect_unusually_long_url(
            raw_url,
            registered_domain,
            query,
            fragment,
        )
    )

    # ========================================================
    # AUTHORITY / @
    # ========================================================

    has_at_symbol = (
        components.get("username")
        is not None
        or components.get("password")
        is not None
    )

    try:

        authority_part = raw_url

        if "://" in authority_part:

            authority_part = (
                authority_part.split(
                    "://",
                    1,
                )[1]
            )

        authority_part = (
            authority_part
            .split("/", 1)[0]
            .split("?", 1)[0]
            .split("#", 1)[0]
        )

        if "@" in authority_part:
            has_at_symbol = True

    except Exception:
        pass

    has_username = bool(
        components.get("username")
    )

    has_password = bool(
        components.get("password")
    )

    # ========================================================
    # PERCENT ENCODING
    # ========================================================

    has_hex_encoding = bool(
        re.search(
            r"%[0-9a-fA-F]{2}",
            raw_url,
        )
    )

    # ========================================================
    # SUSPICIOUS CHARACTERS
    # ========================================================

    has_suspicious_chars = bool(
        re.search(
            r"[\x00-\x1f\x7f\s]",
            evidence_url,
        )
    )

    # ========================================================
    # PUNYCODE
    # ========================================================

    is_punycode = (
        "xn--"
        in hostname.lower()
    )

    # ========================================================
    # TLD
    # ========================================================

    suffix = None

    try:

        extracted = tldextract.extract(
            hostname
        )

        if extracted.suffix:
            suffix = (
                extracted.suffix.lower()
            )

    except Exception:
        suffix = None

    suspicious_tld = (
        suffix in SUSPICIOUS_TLDS
        if suffix
        else False
    )

    # ========================================================
    # TRUSTED EXTERNAL
    # ========================================================

    is_trusted_external = (
        _is_trusted_external_domain(
            registered_domain
        )
    )

    # ========================================================
    # KEYWORDS
    # ========================================================

    matched_keywords = (
        find_suspicious_keywords(
            path,
            query,
            fragment,
        )
    )

    # ========================================================
    # SUSPICIOUS FRAGMENT
    # ========================================================

    has_suspicious_fragment = (
        _detect_suspicious_fragment(
            fragment
        )
    )

    # ========================================================
    # TRACKING PATH
    # ========================================================

    has_tracking_path = (
        _detect_tracking_path(
            path,
            registered_domain,
        )
    )

    # ========================================================
    # OBFUSCATED PATH
    # ========================================================

    has_obfuscated_path = (
        _detect_obfuscated_path(
            path,
            registered_domain,
        )
    )

    # ========================================================
    # SENDER MISMATCH
    # ========================================================

    is_sender_mismatch = False

    if (
        sender_root_domain
        and registered_domain
    ):

        is_sender_mismatch = (
            sender_root_domain.lower()
            != registered_domain.lower()
        )

    # ========================================================
    # FINAL FEATURES
    # ========================================================

    return {
        "url_length":
            url_length,

        "is_http_only":
            is_http_only,

        "is_https":
            is_https,

        "is_defanged":
            is_defanged,

        "is_ip_hostname":
            is_ip_hostname,

        "ip_version":
            ip_version,

        "is_shortener":
            is_shortener,

        "subdomain_count":
            subdomain_count,

        "has_excessive_subdomains":
            has_excessive_subdomains,

        "is_unusually_long":
            is_unusually_long,

        "has_at_symbol":
            has_at_symbol,

        "has_username":
            has_username,

        "has_password":
            has_password,

        "has_hex_encoding":
            has_hex_encoding,

        "has_suspicious_chars":
            has_suspicious_chars,

        "is_punycode":
            is_punycode,

        "matched_keywords":
            matched_keywords,

        "has_suspicious_fragment":
            has_suspicious_fragment,

        "has_tracking_path":
            has_tracking_path,

        "has_obfuscated_path":
            has_obfuscated_path,

        "is_sender_mismatch":
            is_sender_mismatch,

        "is_trusted_external":
            is_trusted_external,

        "suspicious_tld":
            suspicious_tld,

        "tld":
            suffix,

        "is_non_web_reference":
            False,
    }