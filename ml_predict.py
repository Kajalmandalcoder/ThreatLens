import sys
import json
import os
import re
import joblib


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml_model",
    "threat_model.pkl"
)

VECTORIZER_PATH = os.path.join(
    BASE_DIR,
    "ml_model",
    "tfidf_vectorizer.pkl"
)


def analyze_reasons(email_text):
    text = email_text.lower()

    technical_reasons = []
    recommended_actions = []

    # Urgency indicators
    urgency_patterns = [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\bact now\b",
        r"\baccount suspended\b",
        r"\baccount will be suspended\b",
        r"\bverify now\b"
    ]

    # Credential indicators
    credential_patterns = [
        r"\bpassword\b",
        r"\botp\b",
        r"\blogin\b",
        r"\bverify your account\b",
        r"\bsecurity code\b"
    ]

    # Financial indicators
    financial_patterns = [
        r"\bpayment\b",
        r"\bbank\b",
        r"\binvoice\b",
        r"\btransfer\b",
        r"\btransaction\b"
    ]

    # URL indicators
    url_pattern = r"https?://|www\."

    # Attachment indicators
    attachment_patterns = [
        r"\battachment\b",
        r"\battached file\b",
        r"\bdownload\b",
        r"\bopen the attached\b"
    ]

    if any(re.search(pattern, text) for pattern in urgency_patterns):
        technical_reasons.append("URGENCY")
        recommended_actions.append(
            "Verify the request independently before taking action."
        )

    if any(re.search(pattern, text) for pattern in credential_patterns):
        technical_reasons.append("CREDENTIAL_REQUEST")
        recommended_actions.append(
            "Do not enter or share your password, OTP, or security code."
        )

    if re.search(url_pattern, text):
        technical_reasons.append("SUSPICIOUS_URL")
        recommended_actions.append(
            "Do not click links until the sender and destination are verified."
        )

    if any(re.search(pattern, text) for pattern in financial_patterns):
        technical_reasons.append("FINANCIAL_REQUEST")
        recommended_actions.append(
            "Do not transfer money or make payments without independent verification."
        )

    if any(re.search(pattern, text) for pattern in attachment_patterns):
        technical_reasons.append("SUSPICIOUS_ATTACHMENT")
        recommended_actions.append(
            "Do not open or download unexpected attachments."
        )

    return technical_reasons, recommended_actions


def get_risk_level(threat_score):
    if threat_score >= 80:
        return "CRITICAL"
    elif threat_score >= 60:
        return "HIGH"
    elif threat_score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


def main():

    if len(sys.argv) < 2:
        print(json.dumps({
            "success": False,
            "error": "No email text provided"
        }))
        sys.exit(1)

    email_text = sys.argv[1]

    try:

        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)

        email_vector = vectorizer.transform([email_text])

        prediction_label = model.predict(email_vector)[0]

        probabilities = model.predict_proba(email_vector)[0]

        threat_score = round(
            float(probabilities[1]) * 100,
            2
        )

        if prediction_label == 1:
            prediction = "THREAT"
        else:
            prediction = "SAFE"

        technical_reasons, recommended_actions = analyze_reasons(
            email_text
        )

        risk_level = get_risk_level(threat_score)

        print(json.dumps({
            "success": True,
            "prediction": prediction,
            "confidence": threat_score,
            "raw_label": f"LABEL_{prediction_label}",
            "threatScore": threat_score,
            "riskLevel": risk_level,
            "technicalReasons": technical_reasons,
            "recommendedActions": recommended_actions
        }))

    except Exception as error:

        print(json.dumps({
            "success": False,
            "error": str(error)
        }))

        sys.exit(1)


if __name__ == "__main__":
    main()