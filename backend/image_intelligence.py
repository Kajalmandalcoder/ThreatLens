"""
ThreadLens - Image Intelligence Pipeline (Point 7)
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

# ThreadLens modules import
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
# 1. IMAGE EXTRACTION
# ============================================================

def extract_and_save_email_images(msg, save_dir="./extracted_email_images") -> List[str]:
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    extracted_image_paths = []
    image_counter = 1

    # MIME attachments / inline
    for part in msg.walk():
        content_type = part.get_content_type()
        if "image" in content_type:
            payload = part.get_payload(decode=True)
            if payload:
                ext = content_type.split('/')[-1]
                filename = part.get_filename() or f"embedded_img_{image_counter}.{ext}"
                filepath = os.path.join(save_dir, filename)
                with open(filepath, "wb") as f:
                    f.write(payload)
                extracted_image_paths.append(filepath)
                image_counter += 1

    # Base64 in HTML body
    html_content = ""
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            try:
                content = part.get_content()
                if isinstance(content, str):
                    html_content += content
            except Exception:
                pass

    if html_content:
        soup = BeautifulSoup(html_content, 'html.parser')
        for i, img in enumerate(soup.find_all('img')):
            src = img.get('src', '')
            if src.startswith('data:image'):
                try:
                    header, encoded = src.split(",", 1)
                    ext = header.split(";")[0].split("/")[1]
                    image_data = base64.b64decode(encoded)
                    filepath = os.path.join(save_dir, f"html_base64_img_{i+1}.{ext}")
                    with open(filepath, "wb") as f:
                        f.write(image_data)
                    extracted_image_paths.append(filepath)
                except Exception:
                    continue

    return extracted_image_paths


# ============================================================
# 2. OCR
# ============================================================

def extract_text_from_images(image_paths: List[str]) -> Dict[str, str]:
    ocr_results = {}
    for path in image_paths:
        try:
            detected_lines = reader.readtext(path, detail=0)
            text = " ".join(detected_lines).strip()
            ocr_results[path] = text
        except Exception as e:
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

def analyze_suspicious_text(text: str) -> Dict[str, Any]:
    if not text or not text.strip():
        return {
            "has_suspicious_text": False,
            "detected_intents": [],
            "matched_phrases": [],
            "risk_score": 0.0,
            "verdict": "BENIGN"
        }

    clean_text = " ".join(text.lower().split())
    matched_phrases = []
    category_hits = set()

    for category, patterns in THREAT_CATEGORIES.items():
        for pattern in patterns:
            found = re.findall(pattern, clean_text)
            if found:
                category_hits.add(category)
                matched_phrases.extend(found)

    matched_phrases = list(set(matched_phrases))
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
        "has_suspicious_text": risk_score >= 0.50,
        "detected_intents": list(category_hits),
        "matched_phrases": matched_phrases,
        "risk_score": round(risk_score, 2),
        "verdict": verdict
    }


# ============================================================
# 4. QR DETECTION
# ============================================================

def scan_qr_codes(image_paths: List[str], sender_email: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    detector = cv2.QRCodeDetector()
    qr_results = {}

    sender_domain = extract_domain_parts(sender_email).get("registered_domain") if sender_email else None

    for path in image_paths:
        qr_results[path] = []
        try:
            img = cv2.imread(path)
            if img is None:
                continue

            extracted_payloads = []
            data, _, _ = detector.detectAndDecode(img)
            if data:
                extracted_payloads.append(data.strip())
            else:
                retval, decoded_info, _, _ = detector.detectAndDecodeMulti(img)
                if retval:
                    for item in decoded_info:
                        if item.strip():
                            extracted_payloads.append(item.strip())

            # Har QR URL ko url_intelligence se scan karna
            for payload in extracted_payloads:
                url_threat = analyze_single_url(payload, sender_root=sender_domain)
                qr_results[path].append({
                    "payload": payload,
                    "url_intelligence": url_threat
                })

        except Exception as e:
            pass

    return qr_results


# ============================================================
# 5. BRAND / LOGO & IMPERSONATION CHECK
# ============================================================

def detect_visual_logo(image_path: str, threshold: float = 0.70) -> Optional[str]:
    if not os.path.exists(TEMPLATES_DIR):
        return None

    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        return None

    best_brand = None
    highest_score = 0.0

    for filename in os.listdir(TEMPLATES_DIR):
        if not filename.lower().endswith((".png", ".jpg", ".jpeg")):
            continue

        brand_name = os.path.splitext(filename)[0].lower()
        template = cv2.imread(os.path.join(TEMPLATES_DIR, filename), cv2.IMREAD_GRAYSCALE)
        if template is None:
            continue

        t_h, t_w = template.shape[:2]
        for scale in np.linspace(0.3, 1.5, 7):
            resized_w, resized_h = int(t_w * scale), int(t_h * scale)
            if resized_w > img.shape[1] or resized_h > img.shape[0]:
                continue

            resized = cv2.resize(template, (resized_w, resized_h))
            res = cv2.matchTemplate(img, resized, cv2.TM_CCOEFF_NORMED)
            _, max_val, _, _ = cv2.minMaxLoc(res)

            if max_val > highest_score:
                highest_score = max_val
                if max_val >= threshold:
                    best_brand = brand_name

    return best_brand


def check_brand_impersonation(image_path: str, ocr_text: str, sender_email: Optional[str] = None) -> Dict[str, Any]:
    protected_brands = load_brand_targets()

    # Visual detection
    detected_brand = detect_visual_logo(image_path)
    method = "visual"

    # OCR text fallback
    if not detected_brand:
        ocr_lower = ocr_text.lower()
        for brand in protected_brands:
            if re.search(rf"\b{re.escape(brand)}\b", ocr_lower):
                detected_brand = brand
                method = "ocr"
                break

    is_impersonation = False
    reason = None

    if detected_brand and sender_email:
        domain_parts = extract_domain_parts(sender_email)
        domain_name = domain_parts.get("domain_name") or ""
        reg_domain = domain_parts.get("registered_domain") or ""

        if detected_brand not in reg_domain.lower():
            is_impersonation = True
            reason = f"Image contains {detected_brand.title()} brand ({method}), but email sent from '{reg_domain}'."

        # ThreadLens lookalike verification
        lookalike = detect_lookalike_brand(domain_name, protected_brands)
        if lookalike.get("is_lookalike"):
            is_impersonation = True
            reason = f"Image contains {detected_brand.title()} brand, but sender domain '{domain_name}' is a detected typosquatting lookalike."

    return {
        "detected_brand": detected_brand,
        "method": method if detected_brand else None,
        "is_impersonation": is_impersonation,
        "reason": reason
    }


# ============================================================
# 6. MASTER PIPELINE: IMAGE RISK SCORE & VERDICT
# ============================================================

def analyze_email_image_intelligence(msg, sender_email: Optional[str] = None) -> Dict[str, Any]:
    # 1. Extraction
    image_paths = extract_and_save_email_images(msg)

    if not image_paths:
        return {
            "images_analyzed": 0,
            "overall_risk_score": 0,
            "risk_level": "LOW",
            "verdict": "SAFE",
            "reasons": ["No images found in email"],
            "image_details": []
        }

    # 2. OCR & QR
    ocr_results = extract_text_from_images(image_paths)
    qr_results = scan_qr_codes(image_paths, sender_email=sender_email)

    all_image_reports = []
    overall_score = 0
    master_reasons = []

    for path in image_paths:
        text = ocr_results.get(path, "")
        text_analysis = analyze_suspicious_text(text)
        qr_analysis = qr_results.get(path, [])
        brand_data = check_brand_impersonation(path, text, sender_email=sender_email)

        img_score = 0
        img_reasons = []

        # Risk 1: QR URL threat (ThreadLens URL Intelligence integration)
        for item in qr_analysis:
            url_score = item.get("url_intelligence", {}).get("risk_score", 0)
            img_score = max(img_score, url_score)
            if url_score >= 60:
                img_reasons.append(f"QR code points to dangerous URL (Score: {url_score})")
            else:
                img_reasons.append("Embedded QR Code found")

        # Risk 2: Brand Impersonation
        if brand_data["is_impersonation"]:
            img_score += 45
            img_reasons.append(brand_data["reason"])

        # Risk 3: Social Engineering / Phishing Text
        if text_analysis["has_suspicious_text"]:
            img_score += int(text_analysis["risk_score"] * 35)
            img_reasons.append(f"Phishing text intents detected: {', '.join(text_analysis['detected_intents'])}")

        img_score = min(max(img_score, 0), 100)
        overall_score = max(overall_score, img_score)
        master_reasons.extend(img_reasons)

        all_image_reports.append({
            "path": path,
            "ocr_text": text,
            "text_analysis": text_analysis,
            "qr_data": qr_analysis,
            "brand_data": brand_data,
            "risk_score": img_score,
            "reasons": img_reasons
        })

    # Final verdict
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

    return {
        "images_analyzed": len(image_paths),
        "overall_risk_score": overall_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "reasons": list(dict.fromkeys(master_reasons)),
        "image_details": all_image_reports
    }
