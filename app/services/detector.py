import re


def analyze_privacy(text: str):
    risks = []
    protected_text = text

    # -------------------------
    # EMAIL DETECTION
    # -------------------------
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'

    if re.search(email_pattern, text):
        risks.append({
            "type": "EMAIL",
            "description": "Email address detected",
            "severity": "HIGH"
        })

        protected_text = re.sub(
            email_pattern,
            "[EMAIL]",
            protected_text
        )

    # -------------------------
    # PASSWORD / CREDENTIAL
    # -------------------------
    password_pattern = r'(?i)\b(password|passwd|pwd)\s*(is|=|:)\s*[^\s,.]+'

    if re.search(password_pattern, text):
        risks.append({
            "type": "CREDENTIAL",
            "description": "Password or credential detected",
            "severity": "CRITICAL"
        })

        protected_text = re.sub(
            password_pattern,
            lambda m: m.group(1) + " [CREDENTIAL]",
            protected_text
        )

    # -------------------------
    # CONFIDENTIAL BUSINESS INFO
    # -------------------------
    confidential_keywords = [
        "salary",
        "confidential",
        "internal",
        "financial projection",
        "revenue",
        "business plan",
        "company secret",
        "private business"
    ]

    text_lower = text.lower()

    found_confidential = any(
        keyword in text_lower
        for keyword in confidential_keywords
    )

    if found_confidential:
        risks.append({
            "type": "CONFIDENTIAL_BUSINESS",
            "description": "Potentially confidential workplace/business information detected",
            "severity": "HIGH"
        })

    # -------------------------
    # RISK LEVEL
    # -------------------------
    if any(r["severity"] == "CRITICAL" for r in risks):
        privacy_level = "CRITICAL"

    elif any(r["severity"] == "HIGH" for r in risks):
        privacy_level = "HIGH"

    elif risks:
        privacy_level = "MEDIUM"

    else:
        privacy_level = "LOW"

    return {
        "risks": risks,
        "protected_text": protected_text,
        "privacy_level": privacy_level,
        "items_found": len(risks)
    }