def calculate_final_risk(ml_score, header_score, ip_score,
                         domain_score, url_score, attachment_score):

    final_score = (
    ml_score * 0.25 +
    header_score * 0.15 +
    ip_score * 0.15 +
    domain_score * 0.15 +
    url_score * 0.20 +
    attachment_score * 0.10
)

    return round(final_score, 2)

def get_risk_level(final_score):

    if final_score < 30:
        return "LOW"

    elif final_score < 60:
        return "MEDIUM"

    else:
        return "HIGH"

def get_verdict(risk_level):

    if risk_level == "HIGH":
        return "MALICIOUS"

    elif risk_level == "MEDIUM":
        return "SUSPICIOUS"

    else:
        return "SAFE"

def get_score_breakdown(
    ml_score, header_score, ip_score,
    domain_score, url_score, attachment_score,
    ml_reasons=None,
    header_reasons=None,
    ip_reasons=None,
    domain_reasons=None,
    url_reasons=None,
    attachment_reasons=None
):

    return {
        "ml": {
            "score": ml_score,
            "weight": 0.25,
            "weightedScore": round(ml_score * 0.25, 2),
            "reasons": ml_reasons or []
        },

        "header": {
            "score": header_score,
            "weight": 0.15,
            "weightedScore": round(header_score * 0.15, 2),
            "reasons": header_reasons or []
        },

        "ip": {
            "score": ip_score,
            "weight": 0.15,
            "weightedScore": round(ip_score * 0.15, 2),
            "reasons": ip_reasons or []
        },

        "domain": {
            "score": domain_score,
            "weight": 0.15,
            "weightedScore": round(domain_score * 0.15, 2),
            "reasons": domain_reasons or []
        },

        "url": {
            "score": url_score,
            "weight": 0.20,
            "weightedScore": round(url_score * 0.20, 2),
            "reasons": url_reasons or []
        },

        "attachment": {
            "score": attachment_score,
            "weight": 0.10,
            "weightedScore": round(attachment_score * 0.10, 2),
            "reasons": attachment_reasons or []
        }
    }

def generate_final_reason(score_breakdown):

    detected_components = []

    for component, data in score_breakdown.items():
        if data["reasons"]:
            detected_components.append(component)

    if not detected_components:
        return "No significant risk indicators detected"

    if len(detected_components) == 1:
        component = detected_components[0]
        return f"Risk indicators detected in {component.upper()} analysis"

    if len(detected_components) == 2:
        return (
            f"Some {detected_components[0].upper()} and "
            f"{detected_components[1].upper()} inconsistencies detected"
        )

    return "Multiple risk indicators detected across email analysis"

def get_recommended_actions(risk_level):

    if risk_level == "HIGH":
        return [
            "Do not click links or open attachments",
            "Do not reply to the sender",
            "Report the email as suspicious"
        ]

    elif risk_level == "MEDIUM":
        return [
            "Verify the sender and email content before taking action",
            "Avoid clicking suspicious links or opening unexpected attachments"
        ]

    else:
        return [
            "No immediate action required"
        ]

def generate_risk_analysis(
    ml_score, header_score, ip_score,
    domain_score, url_score, attachment_score,
    ml_reasons=None,
    header_reasons=None,
    ip_reasons=None,
    domain_reasons=None,
    url_reasons=None,
    attachment_reasons=None
):

    # 1. Calculate final risk score
    final_score = calculate_final_risk(
        ml_score,
        header_score,
        ip_score,
        domain_score,
        url_score,
        attachment_score
    )

    # 2. Determine risk level
    risk_level = get_risk_level(final_score)

    # 3. Determine verdict
    verdict = get_verdict(risk_level)

    # 4. Generate score breakdown
    score_breakdown = get_score_breakdown(
        ml_score,
        header_score,
        ip_score,
        domain_score,
        url_score,
        attachment_score,
        ml_reasons,
        header_reasons,
        ip_reasons,
        domain_reasons,
        url_reasons,
        attachment_reasons
    )

    # 5. Generate final reason
    final_reason = generate_final_reason(score_breakdown)

    # 6. Generate recommended actions
    recommended_actions = get_recommended_actions(risk_level)

    return {
        "riskAnalysis": {
            "finalRiskScore": final_score,
            "riskLevel": risk_level,
            "verdict": verdict,
            "scoreBreakdown": score_breakdown,
            "finalReasons": [final_reason],
            "recommendedActions": recommended_actions
        }
    }

if __name__ == "__main__":
    import sys
    import json

    input_data = json.loads(sys.stdin.read())

    result = generate_risk_analysis(
        input_data["ml_score"],
        input_data["header_score"],
        input_data["ip_score"],
        input_data["domain_score"],
        input_data["url_score"],
        input_data["attachment_score"],
        input_data.get("ml_reasons"),
        input_data.get("header_reasons"),
        input_data.get("ip_reasons"),
        input_data.get("domain_reasons"),
        input_data.get("url_reasons"),
        input_data.get("attachment_reasons")
    )

    print(json.dumps(result))
