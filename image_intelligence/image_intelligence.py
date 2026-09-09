"""
ThreatLens - Image Intelligence Pipeline
Integrated with URL Intelligence and Domain Intelligence
"""

import os
import re
import cv2
import base64
import numpy as np
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup

import easyocr

from url_intelligence.analyzer import analyze_single_url
from intelligence.domain_intelligence import (
    extract_domain_parts,
    detect_lookalike_brand,
    load_brand_targets
)

# Initialize EasyOCR
reader = easyocr.Reader(['en'], gpu=False)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(CURRENT_DIR, "brand_templates")


# ============================================================
# DEFAULT PROTECTED BRANDS
# ============================================================

DEFAULT_PROTECTED_BRANDS = [
    "microsoft",
    "apple",
    "spotify",
    "paypal",
    "amazon",
    "google",
    "linkedin",
    "facebook",
    "instagram",
    "netflix",
    "adobe",
    "dropbox",
    "docusign",
    "github"
]


# ============================================================
# AUTHORIZED BRAND DOMAINS
# ============================================================

BRAND_DOMAIN_MAP = {

    "microsoft": [
        "microsoft.com",
        "microsoftonline.com",
        "office.com",
        "live.com",
        "outlook.com"
    ],

    "apple": [
        "apple.com",
        "icloud.com"
    ],

    "spotify": [
        "spotify.com"
    ],

    "paypal": [
        "paypal.com"
    ],

    "amazon": [
        "amazon.com",
        "amazon.in"
    ],

    "google": [
        "google.com"
    ],

    "linkedin": [
        "linkedin.com"
    ],

    "facebook": [
        "facebook.com"
    ],

    "instagram": [
        "instagram.com"
    ],

    "netflix": [
        "netflix.com"
    ],

    "adobe": [
        "adobe.com"
    ],

    "dropbox": [
        "dropbox.com"
    ],

    "docusign": [
        "docusign.com"
    ],

    "github": [
        "github.com"
    ]
}


# ============================================================
# 1. IMAGE EXTRACTION
# ============================================================

def extract_and_save_email_images(
    msg,
    save_dir="./extracted_email_images"
) -> List[str]:

    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    extracted_image_paths = []
    image_counter = 1

    # ========================================================
    # MIME / ATTACHED / INLINE IMAGES
    # ========================================================

    for part in msg.walk():

        content_type = part.get_content_type()

        if content_type.startswith("image/"):

            payload = part.get_payload(decode=True)

            if not payload:
                continue

            ext = content_type.split("/")[-1].lower()

            if ext == "jpeg":
                ext = "jpg"

            filename = part.get_filename()

            if not filename:
                filename = f"embedded_img_{image_counter}.{ext}"

            filename = os.path.basename(filename)

            filepath = os.path.join(
                save_dir,
                filename
            )

            base, extension = os.path.splitext(filepath)

            counter = 1

            while os.path.exists(filepath):

                filepath = (
                    f"{base}_{counter}{extension}"
                )

                counter += 1

            try:

                with open(filepath, "wb") as f:
                    f.write(payload)

                extracted_image_paths.append(filepath)
                image_counter += 1

            except Exception:
                continue

    # ========================================================
    # HTML BODY
    # ========================================================

    html_content = ""

    for part in msg.walk():

        if part.get_content_type() == "text/html":

            try:

                content = part.get_content()

                if isinstance(content, str):
                    html_content += content

            except Exception:
                continue

    if not html_content:
        return extracted_image_paths

    soup = BeautifulSoup(
        html_content,
        "html.parser"
    )

    # ========================================================
    # BASE64 HTML IMAGES
    # ========================================================

    for i, img in enumerate(
        soup.find_all("img"),
        start=1
    ):

        src = img.get("src", "")

        if not src:
            continue

        if src.startswith("data:image"):

            try:

                header, encoded = src.split(
                    ",",
                    1
                )

                image_format = (
                    header
                    .split(";")[0]
                    .split("/")[1]
                )

                if image_format == "jpeg":
                    image_format = "jpg"

                image_data = base64.b64decode(
                    encoded
                )

                filepath = os.path.join(
                    save_dir,
                    f"html_base64_img_{i}.{image_format}"
                )

                with open(filepath, "wb") as f:
                    f.write(image_data)

                extracted_image_paths.append(
                    filepath
                )

            except Exception:
                continue

    # ========================================================
    # REMOTE HTTP / HTTPS IMAGES
    # ========================================================

    remote_urls = []

    for img in soup.find_all("img"):

        src = img.get("src", "").strip()

        if (
            src.startswith("http://")
            or src.startswith("https://")
        ):
            remote_urls.append(src)

    if remote_urls:

        try:

            import requests

            for i, image_url in enumerate(
                remote_urls,
                start=1
            ):

                try:

                    response = requests.get(
                        image_url,
                        timeout=10,
                        headers={
                            "User-Agent": "Mozilla/5.0"
                        }
                    )

                    if response.status_code != 200:
                        continue

                    content_type = response.headers.get(
                        "Content-Type",
                        ""
                    ).lower()

                    if not content_type.startswith(
                        "image/"
                    ):
                        continue

                    image_bytes = response.content

                    extension = (
                        content_type
                        .split("/")[-1]
                    )

                    if extension == "jpeg":
                        extension = "jpg"

                    if extension not in [
                        "jpg",
                        "png",
                        "gif",
                        "bmp",
                        "webp",
                        "tiff"
                    ]:
                        extension = "jpg"

                    filepath = os.path.join(
                        save_dir,
                        f"remote_img_{i}.{extension}"
                    )

                    with open(filepath, "wb") as f:
                        f.write(image_bytes)

                    extracted_image_paths.append(
                        filepath
                    )

                except Exception:
                    continue

        except ImportError:

            print(
                "WARNING: requests library not installed. "
                "Remote images were not downloaded."
            )

    return extracted_image_paths


# ============================================================
# 2. OCR
# ============================================================

def extract_text_from_images(
    image_paths: List[str]
) -> Dict[str, str]:

    ocr_results = {}

    for path in image_paths:

        try:

            detected_lines = reader.readtext(
                path,
                detail=0
            )

            text = " ".join(
                detected_lines
            ).strip()

            ocr_results[path] = text

        except Exception:

            ocr_results[path] = ""

    return ocr_results


# ============================================================
# 3. SUSPICIOUS TEXT DETECTION
# ============================================================

THREAT_CATEGORIES = {

    "urgency": [
        r"\b(?:urgent|immediately|within \d+ (?:hours?|days?)|final notice|action required|time sensitive)\b",
        r"\b(?:deadline|expires?|suspended|terminated|restricted)\b",
    ],

    "financial_credentials": [
        r"\b(?:reset password|verify account|update (?:billing|payment|kyc)|confirm identity)\b",
        r"\b(?:unauthorized (?:access|login)|security alert|otp|wire transfer|refund|invoice)\b",
    ],

    "call_to_action": [
        r"\b(?:click here|scan (?:the )?(?:qr|code)|login to your account|follow this link)\b",
        r"\b(?:download attachment|view document|claim now)\b",
    ]
}


def analyze_suspicious_text(
    text: str
) -> Dict[str, Any]:

    if not text or not text.strip():

        return {
            "has_suspicious_text": False,
            "detected_intents": [],
            "matched_phrases": [],
            "risk_score": 0.0,
            "verdict": "BENIGN"
        }

    clean_text = " ".join(
        text.lower().split()
    )

    matched_phrases = []
    category_hits = set()

    for category, patterns in THREAT_CATEGORIES.items():

        for pattern in patterns:

            found = re.findall(
                pattern,
                clean_text
            )

            if found:

                category_hits.add(category)
                matched_phrases.extend(
                    found
                )

    matched_phrases = list(
        set(matched_phrases)
    )

    hits_count = len(category_hits)

    if hits_count >= 3:

        risk_score = 0.95
        verdict = "CRITICAL_PHISHING"

    elif hits_count == 2:

        risk_score = 0.70
        verdict = "SUSPICIOUS"

    elif hits_count == 1:

        risk_score = 0.35
        verdict = "LOW_RISK"

    else:

        risk_score = 0.0
        verdict = "BENIGN"

    return {

        "has_suspicious_text":
            risk_score >= 0.50,

        "detected_intents":
            list(category_hits),

        "matched_phrases":
            matched_phrases,

        "risk_score":
            round(risk_score, 2),

        "verdict":
            verdict
    }


# ============================================================
# 4. QR DETECTION
# ============================================================

def scan_qr_codes(
    image_paths: List[str],
    sender_email: Optional[str] = None
) -> Dict[str, List[Dict[str, Any]]]:

    detector = cv2.QRCodeDetector()
    qr_results = {}

    sender_domain = (
        extract_domain_parts(
            sender_email
        ).get("registered_domain")
        if sender_email
        else None
    )

    for path in image_paths:

        qr_results[path] = []

        try:

            img = cv2.imread(path)

            if img is None:
                continue

            extracted_payloads = []

            # Single QR
            data, _, _ = detector.detectAndDecode(
                img
            )

            if data:

                extracted_payloads.append(
                    data.strip()
                )

            else:

                # Multiple QR
                retval, decoded_info, _, _ = (
                    detector.detectAndDecodeMulti(
                        img
                    )
                )

                if retval:

                    for item in decoded_info:

                        if item.strip():

                            extracted_payloads.append(
                                item.strip()
                            )

            # Remove duplicates
            extracted_payloads = list(
                dict.fromkeys(
                    extracted_payloads
                )
            )

            # QR payload → URL Intelligence
            for payload in extracted_payloads:

                url_threat = analyze_single_url(
                    payload,
                    sender_root=sender_domain
                )

                qr_results[path].append({

                    "payload": payload,

                    "url_intelligence":
                        url_threat
                })

        except Exception:
            pass

    return qr_results


# ============================================================
# 5. VISUAL LOGO DETECTION
# ============================================================

def detect_visual_logo(
    image_path: str,
    threshold: float = 0.70
) -> Optional[str]:

    if not os.path.exists(
        TEMPLATES_DIR
    ):
        return None

    img = cv2.imread(
        image_path,
        cv2.IMREAD_GRAYSCALE
    )

    if img is None:
        return None

    best_brand = None
    highest_score = 0.0

    for filename in os.listdir(
        TEMPLATES_DIR
    ):

        if not filename.lower().endswith(
            (".png", ".jpg", ".jpeg")
        ):
            continue

        brand_name = os.path.splitext(
            filename
        )[0].lower()

        template = cv2.imread(
            os.path.join(
                TEMPLATES_DIR,
                filename
            ),
            cv2.IMREAD_GRAYSCALE
        )

        if template is None:
            continue

        t_h, t_w = template.shape[:2]

        for scale in np.linspace(
            0.3,
            1.5,
            7
        ):

            resized_w = int(
                t_w * scale
            )

            resized_h = int(
                t_h * scale
            )

            if (
                resized_w <= 0
                or resized_h <= 0
            ):
                continue

            if (
                resized_w > img.shape[1]
                or resized_h > img.shape[0]
            ):
                continue

            resized = cv2.resize(
                template,
                (
                    resized_w,
                    resized_h
                )
            )

            try:

                res = cv2.matchTemplate(
                    img,
                    resized,
                    cv2.TM_CCOEFF_NORMED
                )

                _, max_val, _, _ = (
                    cv2.minMaxLoc(res)
                )

                if max_val > highest_score:

                    highest_score = max_val

                    if max_val >= threshold:

                        best_brand = (
                            brand_name
                        )

            except Exception:
                continue

    return best_brand


# ============================================================
# 6. BRAND / LOGO & IMPERSONATION
# ============================================================

def check_brand_impersonation(
    image_path: str,
    ocr_text: str,
    sender_email: Optional[str] = None
) -> Dict[str, Any]:

    # ========================================================
    # LOAD BRAND TARGETS
    # ========================================================

    try:

        loaded_brands = (
            load_brand_targets()
        )

    except Exception:

        loaded_brands = []

    protected_brands = set()

    if loaded_brands:

        for brand in loaded_brands:

            if isinstance(brand, str):

                clean_brand = (
                    brand.strip().lower()
                )

                if clean_brand:
                    protected_brands.add(
                        clean_brand
                    )

    # Always include defaults
    protected_brands.update(
        DEFAULT_PROTECTED_BRANDS
    )

    # ========================================================
    # VISUAL LOGO DETECTION
    # ========================================================

    detected_brand = detect_visual_logo(
        image_path
    )

    method = (
        "visual"
        if detected_brand
        else None
    )

    # ========================================================
    # OCR FALLBACK
    # ========================================================

    if not detected_brand and ocr_text:

        normalized_ocr = " ".join(
            ocr_text.lower().split()
        )

        # Longest first
        for brand in sorted(
            protected_brands,
            key=len,
            reverse=True
        ):

            pattern = (
                rf"\b{re.escape(brand)}\b"
            )

            if re.search(
                pattern,
                normalized_ocr,
                re.IGNORECASE
            ):

                detected_brand = brand
                method = "ocr"
                break

    # ========================================================
    # DEFAULT
    # ========================================================

    is_impersonation = False
    reason = None
    risk_score = 0

    # ========================================================
    # SENDER DOMAIN CHECK
    # ========================================================

    if detected_brand:

        detected_brand = (
            detected_brand
            .lower()
            .strip()
        )

        if sender_email:

            try:

                domain_parts = (
                    extract_domain_parts(
                        sender_email
                    )
                )

                domain_name = (
                    domain_parts.get(
                        "domain_name"
                    )
                    or ""
                ).lower()

                reg_domain = (
                    domain_parts.get(
                        "registered_domain"
                    )
                    or ""
                ).lower()

            except Exception:

                domain_name = ""
                reg_domain = ""

            authorized_domains = (
                BRAND_DOMAIN_MAP.get(
                    detected_brand,
                    []
                )
            )

            # =================================================
            # CHECK AUTHORIZED DOMAIN
            # =================================================

            sender_matches_brand = any(

                reg_domain == allowed_domain

                or reg_domain.endswith(
                    "." + allowed_domain
                )

                for allowed_domain
                in authorized_domains
            )

            # =================================================
            # BRAND / SENDER MISMATCH
            # =================================================

            if not sender_matches_brand:

                is_impersonation = True
                risk_score = 45

                reason = (
                    f"Image contains "
                    f"{detected_brand.title()} "
                    f"branding ({method}), but "
                    f"email was sent from "
                    f"'{reg_domain}'."
                )

            # =================================================
            # LOOKALIKE DOMAIN CHECK
            # =================================================

            try:

                lookalike = (
                    detect_lookalike_brand(
                        domain_name,
                        list(protected_brands)
                    )
                )

                if lookalike.get(
                    "is_lookalike"
                ):

                    is_impersonation = True

                    risk_score = max(
                        risk_score,
                        60
                    )

                    reason = (
                        f"Image contains "
                        f"{detected_brand.title()} "
                        f"branding, but sender "
                        f"domain '{domain_name}' "
                        f"appears to be a brand "
                        f"lookalike."
                    )

            except Exception:
                pass

    return {

        "detected_brand": (
            detected_brand.title()
            if detected_brand
            else None
        ),

        "method": method,

        "is_impersonation":
            is_impersonation,

        "reason":
            reason,

        "risk_score":
            risk_score
    }


# ============================================================
# 7. MASTER IMAGE INTELLIGENCE PIPELINE
# ============================================================

def analyze_email_image_intelligence(
    msg,
    sender_email: Optional[str] = None
) -> Dict[str, Any]:

    # ========================================================
    # IMAGE EXTRACTION
    # ========================================================

    image_paths = (
        extract_and_save_email_images(msg)
    )

    if not image_paths:

        return {

            "images_analyzed": 0,

            "overall_risk_score": 0,

            "risk_level": "LOW",

            "verdict": "SAFE",

            "reasons": [
                "No images found in email"
            ],

            "image_details": []
        }

    # ========================================================
    # OCR + QR
    # ========================================================

    ocr_results = (
        extract_text_from_images(
            image_paths
        )
    )

    qr_results = (
        scan_qr_codes(
            image_paths,
            sender_email=sender_email
        )
    )

    all_image_reports = []

    overall_score = 0

    master_reasons = []

    # ========================================================
    # PROCESS EACH IMAGE
    # ========================================================

    for path in image_paths:

        text = ocr_results.get(
            path,
            ""
        )

        text_analysis = (
            analyze_suspicious_text(
                text
            )
        )

        qr_analysis = qr_results.get(
            path,
            []
        )

        brand_data = (
            check_brand_impersonation(
                path,
                text,
                sender_email=sender_email
            )
        )

        img_score = 0

        img_reasons = []

        # ====================================================
        # RISK 1: QR URL
        # ====================================================

        for item in qr_analysis:

            url_score = (
                item
                .get("url_intelligence", {})
                .get("risk_score", 0)
            )

            img_score = max(
                img_score,
                url_score
            )

            if url_score >= 60:

                img_reasons.append(
                    f"QR code points to "
                    f"dangerous URL "
                    f"(Score: {url_score})"
                )

            else:

                img_reasons.append(
                    "Embedded QR Code found"
                )

        # ====================================================
        # RISK 2: BRAND IMPERSONATION
        # ====================================================

        if brand_data.get(
            "is_impersonation"
        ):

            brand_score = (
                brand_data.get(
                    "risk_score",
                    45
                )
            )

            img_score += brand_score

            if brand_data.get("reason"):

                img_reasons.append(
                    brand_data["reason"]
                )

        # ====================================================
        # RISK 3: SUSPICIOUS TEXT
        # ====================================================

        if text_analysis.get(
            "has_suspicious_text"
        ):

            text_score = int(
                text_analysis[
                    "risk_score"
                ] * 35
            )

            img_score += text_score

            img_reasons.append(
                "Phishing text intents "
                f"detected: "
                f"{', '.join(text_analysis['detected_intents'])}"
            )

        # ====================================================
        # LIMIT SCORE
        # ====================================================

        img_score = min(
            max(img_score, 0),
            100
        )

        overall_score = max(
            overall_score,
            img_score
        )

        master_reasons.extend(
            img_reasons
        )

        # ====================================================
        # IMAGE REPORT
        # ====================================================

        all_image_reports.append({

            "path": path,

            "ocr_text": text,

            "text_analysis":
                text_analysis,

            "qr_data":
                qr_analysis,

            "brand_data":
                brand_data,

            "risk_score":
                img_score,

            "reasons":
                img_reasons
        })

    # ========================================================
    # FINAL VERDICT
    # ========================================================

    if overall_score >= 75:

        risk_level = "CRITICAL"
        verdict = "MALICIOUS"

    elif overall_score >= 50:

        risk_level = "HIGH"
        verdict = "SUSPICIOUS"

    elif overall_score >= 25:

        risk_level = "MEDIUM"
        verdict = "SUSPICIOUS"

    else:

        risk_level = "LOW"
        verdict = "SAFE"

    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {

        "images_analyzed":
            len(image_paths),

        "overall_risk_score":
            overall_score,

        "risk_level":
            risk_level,

        "verdict":
            verdict,

        "reasons":
            list(
                dict.fromkeys(
                    master_reasons
                )
            ),

        "image_details":
            all_image_reports
    }