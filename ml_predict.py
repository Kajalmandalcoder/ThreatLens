import json
import os
import re
import sys
import joblib
from scipy.sparse import hstack


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml_model",
    "threat_model_4class.pkl"
)

WORD_VECTORIZER_PATH = os.path.join(
    BASE_DIR,
    "ml_model",
    "word_tfidf_vectorizer.pkl"
)




def analyze_reasons(email_text):
    text = email_text.lower()

    technical_reasons = []
    recommended_actions = []

    # --------------------------------------------------
    # URGENCY / THREAT LANGUAGE
    # --------------------------------------------------

    urgency_patterns = [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\basap\b",
        r"\bact now\b",
        r"\bwithin \d+ (hour|hours|minute|minutes)\b",
        r"\blast warning\b",
        r"\bdo not delay\b",
        r"\baccount (will be|has been) suspended\b",
        r"\baccount (will be|has been) blocked\b",
        r"\baccount (will be|has been) locked\b",
        r"\baccount (will be|has been) disabled\b",
        r"\bdeleted\b",
        r"\bexpiration\b",
        r"\bexpires today\b"
    ]

    if any(re.search(pattern, text) for pattern in urgency_patterns):
        technical_reasons.append("URGENCY")
        recommended_actions.append(
            "Verify the request independently before taking action."
        )

    # --------------------------------------------------
    # CREDENTIAL / PASSWORD / OTP
    # --------------------------------------------------

    credential_patterns = [
        r"\bpassword\b",
        r"\bpasscode\b",
        r"\botp\b",
        r"\bone[- ]time password\b",
        r"\bsecurity code\b",
        r"\bverification code\b",
        r"\blogin\b",
        r"\blog[- ]in\b",
        r"\blogin details\b",
        r"\bcredentials?\b",
        r"\busername\b",
        r"\benter your password\b",
        r"\bprovide your password\b",
        r"\bverify your account\b",
        r"\bconfirm your account\b"
    ]

    if any(re.search(pattern, text) for pattern in credential_patterns):
        technical_reasons.append("CREDENTIAL_REQUEST")
        recommended_actions.append(
            "Do not enter or share passwords, OTPs, security codes, or login credentials."
        )

    # --------------------------------------------------
    # FINANCIAL / PAYMENT
    # --------------------------------------------------

    financial_patterns = [
        r"\bpayment\b",
        r"\bpay now\b",
        r"\bbilling\b",
        r"\bbilling details\b",
        r"\bpayment method\b",
        r"\bbank\b",
        r"\bbank account\b",
        r"\binvoice\b",
        r"\btransfer\b",
        r"\bwire transfer\b",
        r"\btransaction\b",
        r"\brefund\b",
        r"\bsubscription\b",
        r"\brenew\b",
        r"\bcredit card\b",
        r"\bdebit card\b",
        r"\bcard details\b"
    ]

    if any(re.search(pattern, text) for pattern in financial_patterns):
        technical_reasons.append("FINANCIAL_REQUEST")
        recommended_actions.append(
            "Do not make payments or provide financial information without independent verification."
        )

    # --------------------------------------------------
    # ACCOUNT VERIFICATION / TAKEOVER
    # --------------------------------------------------

    verification_patterns = [
        r"\bverify your account\b",
        r"\bverify account\b",
        r"\baccount verification\b",
        r"\bconfirm your account\b",
        r"\bconfirm account\b",
        r"\bverify your identity\b",
        r"\bconfirm your identity\b",
        r"\bverify your information\b",
        r"\bconfirm your information\b"
    ]

    if any(re.search(pattern, text) for pattern in verification_patterns):
        technical_reasons.append("ACCOUNT_VERIFICATION")
        recommended_actions.append(
            "Access the account through its official website or app instead of the email link."
        )

    takeover_patterns = [
        r"\baccount takeover\b",
        r"\baccount compromised\b",
        r"\bunauthorized login\b",
        r"\bsuspicious login\b",
        r"\bnew login detected\b",
        r"\breset your password\b",
        r"\bchange your password\b",
        r"\bunusual activity\b",
        r"\bunauthorized activity\b",
        r"\bsecure your account\b",
        r"\bunlock your account\b",
        r"\brecover your account\b"
    ]

    if any(re.search(pattern, text) for pattern in takeover_patterns):
        technical_reasons.append("ACCOUNT_TAKEOVER")
        recommended_actions.append(
            "Verify account activity directly through the official service."
        )

    # --------------------------------------------------
    # SUSPICIOUS URL / CTA
    # --------------------------------------------------

    url_pattern = r"(https?://|www\.|hxxps?://|hxxp://)"

    cta_patterns = [
        r"\bclick here\b",
        r"\bclick (the )?(link|button)\b",
        r"\bclick below\b",
        r"\bclick to\b",
        r"\bverify now\b",
        r"\bconfirm now\b",
        r"\bactivate now\b",
        r"\bupdate now\b",
        r"\breset now\b",
        r"\breview billing\b",
        r"\bdownload now\b",
        r"\btake action\b",
        r"\bcomplete verification\b"
    ]

    has_url = re.search(url_pattern, text)
    has_cta = any(re.search(pattern, text) for pattern in cta_patterns)

    if has_url or has_cta:
        technical_reasons.append("SUSPICIOUS_URL")
        recommended_actions.append(
            "Do not click links until the sender and destination are independently verified."
        )

    # --------------------------------------------------
    # ATTACHMENT / DOWNLOAD
    # --------------------------------------------------

    attachment_patterns = [
        r"\battachment\b",
        r"\battached file\b",
        r"\bdownload\b",
        r"\bopen the attached\b",
        r"\bopen attachment\b"
    ]

    if any(re.search(pattern, text) for pattern in attachment_patterns):
        technical_reasons.append("SUSPICIOUS_ATTACHMENT")
        recommended_actions.append(
            "Do not open or download unexpected attachments."
        )

    # Remove duplicates while preserving order
    technical_reasons = list(dict.fromkeys(technical_reasons))
    recommended_actions = list(dict.fromkeys(recommended_actions))

    return technical_reasons, recommended_actions


def get_risk_level(confidence, prediction):
    if prediction == "BENIGN" and confidence >= 60:
        return "LOW"
    elif prediction == "BENIGN":
        return "MEDIUM"
    elif confidence >= 70:
        return "CRITICAL"
    elif confidence >= 50:
        return "HIGH"
    else:
        return "MEDIUM"


def main():

    try:
        # --------------------------------------------------
        # READ INPUT FROM NODE.JS STDIN
        # --------------------------------------------------

        raw_input = sys.stdin.read().strip()

        if not raw_input:
            print(json.dumps({
                "success": False,
                "error": "No input data provided"
            }))
            sys.exit(1)

        input_data = json.loads(raw_input)

        email_text = input_data.get("text", "")
        explanation_text = input_data.get(
            "explanationText",
            email_text
        )

        if not email_text:
            print(json.dumps({
                "success": False,
                "error": "No email text provided"
            }))
            sys.exit(1)

        # --------------------------------------------------
        # LOAD MODEL + VECTORIZERS
        # --------------------------------------------------

        model = joblib.load(MODEL_PATH)

        word_vectorizer = joblib.load(
            WORD_VECTORIZER_PATH
        )

        # --------------------------------------------------
        # VECTORIZE EMAIL
        # --------------------------------------------------

        email_vector = word_vectorizer.transform(
            [email_text]
        )

        # --------------------------------------------------
        # MODEL PREDICTION
        # --------------------------------------------------

        prediction_label = model.predict(
            email_vector
        )[0]

        probabilities = model.predict_proba(
            email_vector
        )[0]

        prediction = str(prediction_label)

        probability_map = {
            str(label): round(
                float(probability) * 100,
                2
            )
            for label, probability in zip(
                model.classes_,
                probabilities
            )
        }

        # --------------------------------------------------
        # THREAT SCORE
        # --------------------------------------------------

        threat_score = round(
            100 - probability_map.get(
                "BENIGN",
                0
            ),
            2
        )

        # --------------------------------------------------
        # EXPLAINABILITY
        # --------------------------------------------------
        
                # --------------------------------------------------
        # EXPLAINABILITY
        # --------------------------------------------------

        technical_reasons, recommended_actions = analyze_reasons(
            explanation_text
        )

        if prediction == "BENIGN":
            if not technical_reasons:
                technical_reasons = [
                    "No strong phishing, malware, BEC, or spam indicators detected."
                ]

            if not recommended_actions:
                recommended_actions = [
                    "No immediate action required; continue normal email precautions."
                ]

        confidence = round(
            float(max(probabilities)) * 100,
            2
        )

        risk_level = get_risk_level(
            confidence,
            prediction
        )

        # --------------------------------------------------
        # FINAL JSON OUTPUT
        # --------------------------------------------------

        result = {
            "success": True,

            # 5-class ML prediction
            "prediction": prediction,
            "confidence": confidence,

            # Class probabilities
            "phishingProbability": probability_map.get(
                "PHISHING",
                0
            ),

            "benignProbability": probability_map.get(
                "BENIGN",
                0
            ),

            "malwareProbability": probability_map.get(
                "MALWARE",
                0
            ),

            "becProbability": probability_map.get(
                "BEC",
                0
            ),

            "spamProbability": probability_map.get(
                "SPAM",
                0
            ),

            # Existing ThreatLens fields
            "raw_label": f"LABEL_{prediction_label}",

            "threatScore": threat_score,

            "riskLevel": risk_level,

            # Model information
            "model": {
                "name": (
                    "ThreatLens 4-Class "
                    "TF-IDF + Logistic Regression"
                ),
                "version": "4-class-v4"
            },

            # ML explanation
            "mlExplanation": {
                "technicalReasons": technical_reasons,
                "recommendedActions": recommended_actions
            },

            # Compatibility fields
            "technicalReasons": technical_reasons,
            "recommendedActions": recommended_actions
        }

        print(json.dumps(result))

    except Exception as error:

        print(json.dumps({
            "success": False,
            "error": str(error)
        }))

        sys.exit(1)


if __name__ == "__main__":
    main()