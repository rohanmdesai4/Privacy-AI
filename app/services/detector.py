import re
from typing import List, Dict, Any


class PrivacyDetector:
    """
    Context-aware privacy detector.

    Detects sensitive workplace information using:
    - surrounding context
    - financial context
    - credentials/secrets
    - personal information
    - confidential/internal project information

    Returns structured detections that can be consumed
    by the existing privacy/redaction service.
    """

    def __init__(self):
        # Financial terms are used as contextual signals,
        # not as the final decision by themselves.
        self.FINANCIAL_KEYWORDS = [
            "revenue",
            "profit",
            "loss",
            "financial",
            "budget",
            "forecast",
            "projection",
            "sales",
            "earnings",
            "investment",
            "funding",
            "salary",
            "cost",
            "expense",
            "pricing",
            "margin",
            "turnover",
        ]

        self.CONFIDENTIAL_KEYWORDS = [
            "confidential",
            "internal",
            "private",
            "secret",
            "restricted",
            "proprietary",
            "not for public",
            "internal use only",
            "company confidential",
        ]

        self.PROJECT_KEYWORDS = [
            "internal project",
            "company project",
            "unreleased project",
            "upcoming project",
            "product roadmap",
            "business plan",
            "internal strategy",
            "company strategy",
            "future product",
        ]

        self.CREDENTIAL_KEYWORDS = [
            "password",
            "passwd",
            "api key",
            "apikey",
            "access token",
            "token",
            "secret key",
            "private key",
            "authentication key",
            "credentials",
        ]

    # ---------------------------------------------------------
    # MAIN DETECTION FUNCTION
    # ---------------------------------------------------------

    def detect(self, text: str) -> List[Dict[str, Any]]:
        """
        Analyze text and return detected sensitive information.
        """

        if not text or not text.strip():
            return []

        detections = []

        lower_text = text.lower()

        # -----------------------------------------------------
        # 1. CREDENTIAL / SECRET DETECTION
        # -----------------------------------------------------

        credential_patterns = [
            r"(?i)\b(api[_ -]?key)\b",
            r"(?i)\b(access[_ -]?token)\b",
            r"(?i)\b(secret[_ -]?key)\b",
            r"(?i)\b(password|passwd)\b",
            r"(?i)\b(private[_ -]?key)\b",
        ]

        for pattern in credential_patterns:
            match = re.search(pattern, text)

            if match:
                detections.append(
                    {
                        "entity_type": "CREDENTIAL",
                        "text": match.group(0),
                        "start": match.start(),
                        "end": match.end(),
                        "confidence": 0.97,
                        "risk_level": "CRITICAL",
                        "reason": "Text contains credential or authentication-related information.",
                        "action": "REDACT",
                    }
                )

                return detections

        # -----------------------------------------------------
        # 2. EMAIL DETECTION
        # -----------------------------------------------------

        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

        email_match = re.search(email_pattern, text)

        if email_match:

            detections.append(
                {
                    "entity_type": "EMAIL",
                    "text": email_match.group(0),
                    "start": email_match.start(),
                    "end": email_match.end(),
                    "confidence": 0.98,
                    "risk_level": "HIGH",
                    "reason": "Text contains an email address.",
                    "action": "REDACT",
                }
            )

        # -----------------------------------------------------
        # 3. PHONE NUMBER DETECTION
        # -----------------------------------------------------

        phone_pattern = r"(?<!\d)(?:\+91[-\s]?)?[6-9]\d{9}(?!\d)"

        phone_match = re.search(phone_pattern, text)

        if phone_match:

            detections.append(
                {
                    "entity_type": "PHONE",
                    "text": phone_match.group(0),
                    "start": phone_match.start(),
                    "end": phone_match.end(),
                    "confidence": 0.95,
                    "risk_level": "HIGH",
                    "reason": "Text contains a phone number.",
                    "action": "REDACT",
                }
            )

        # -----------------------------------------------------
        # 4. FINANCIAL CONTEXT DETECTION
        # -----------------------------------------------------

        financial_matches = []

        for keyword in self.FINANCIAL_KEYWORDS:

            if keyword in lower_text:
                financial_matches.append(keyword)

        # Strong financial context
        financial_numbers = re.findall(
            r"(?:₹|\$|€|£)\s?\d+(?:[,.]\d+)*(?:\s?(?:million|billion|lakh|crore|k|m|bn))?",
            text,
            flags=re.IGNORECASE,
        )

        percentage_matches = re.findall(
            r"\b\d+(?:\.\d+)?\s?%",
            text,
        )

        if financial_matches and (financial_numbers or percentage_matches):

            keyword = financial_matches[0]

            detections.append(
                {
                    "entity_type": "CONFIDENTIAL_FINANCIAL",
                    "text": text,
                    "start": 0,
                    "end": len(text),
                    "confidence": 0.96,
                    "risk_level": "HIGH",
                    "reason": (
                        f"Text contains financial information in a sensitive "
                        f"context involving '{keyword}'."
                    ),
                    "action": "REDACT",
                }
            )

            return detections

        # Financial context without obvious number
        if len(financial_matches) >= 2:

            keyword = financial_matches[0]

            detections.append(
                {
                    "entity_type": "CONFIDENTIAL_FINANCIAL",
                    "text": text,
                    "start": 0,
                    "end": len(text),
                    "confidence": 0.88,
                    "risk_level": "HIGH",
                    "reason": (
                        "Multiple financial concepts occur together, "
                        f"including '{keyword}', indicating potentially "
                        "confidential business information."
                    ),
                    "action": "REDACT",
                }
            )

            return detections

        # -----------------------------------------------------
        # 5. CONFIDENTIAL BUSINESS CONTEXT
        # -----------------------------------------------------

        confidential_matches = [
            keyword
            for keyword in self.CONFIDENTIAL_KEYWORDS
            if keyword in lower_text
        ]

        project_matches = [
            keyword
            for keyword in self.PROJECT_KEYWORDS
            if keyword in lower_text
        ]

        # Strong context:
        # confidential/internal + project/business information
        if confidential_matches and project_matches:

            detections.append(
                {
                    "entity_type": "CONFIDENTIAL_PROJECT",
                    "text": text,
                    "start": 0,
                    "end": len(text),
                    "confidence": 0.94,
                    "risk_level": "HIGH",
                    "reason": (
                        "Text combines confidentiality indicators with "
                        "internal project or business information."
                    ),
                    "action": "REDACT",
                }
            )

            return detections

        # Internal/confidential text with business terms
        business_context = [
            "strategy",
            "roadmap",
            "client",
            "customer",
            "product",
            "launch",
            "development",
            "business",
            "company",
        ]

        business_matches = [
            keyword
            for keyword in business_context
            if keyword in lower_text
        ]

        if confidential_matches and business_matches:

            detections.append(
                {
                    "entity_type": "CONFIDENTIAL_BUSINESS",
                    "text": text,
                    "start": 0,
                    "end": len(text),
                    "confidence": 0.91,
                    "risk_level": "HIGH",
                    "reason": (
                        "Confidentiality language appears together with "
                        "business-related information."
                    ),
                    "action": "REDACT",
                }
            )

            return detections

        # -----------------------------------------------------
        # 6. INTERNAL PROJECT WITHOUT EXPLICIT "CONFIDENTIAL"
        # -----------------------------------------------------

        if len(project_matches) >= 1:

            detections.append(
                {
                    "entity_type": "INTERNAL_PROJECT",
                    "text": text,
                    "start": 0,
                    "end": len(text),
                    "confidence": 0.82,
                    "risk_level": "MEDIUM",
                    "reason": (
                        "Text contains indicators of an internal or "
                        "unreleased company project."
                    ),
                    "action": "REDACT",
                }
            )

            return detections

        # -----------------------------------------------------
        # 7. CONFIDENTIAL WORD + SENSITIVE BUSINESS CONTEXT
        # -----------------------------------------------------

        sensitive_context_words = [
            "employee",
            "customer",
            "client",
            "contract",
            "agreement",
            "database",
            "server",
            "security",
            "architecture",
            "deployment",
            "research",
            "algorithm",
            "model",
        ]

        sensitive_matches = [
            keyword
            for keyword in sensitive_context_words
            if keyword in lower_text
        ]

        if confidential_matches and sensitive_matches:

            detections.append(
                {
                    "entity_type": "CONFIDENTIAL_INFORMATION",
                    "text": text,
                    "start": 0,
                    "end": len(text),
                    "confidence": 0.90,
                    "risk_level": "HIGH",
                    "reason": (
                        "Confidentiality language occurs alongside "
                        "potentially sensitive workplace information."
                    ),
                    "action": "REDACT",
                }
            )
            return detections

        # -----------------------------------------------------
        # 8. NO SENSITIVE INFORMATION FOUND
        # -----------------------------------------------------

        return detections
detector = PrivacyDetector()