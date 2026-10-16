import re
from typing import List, Dict


class PrivacyDetector:
    """
    Temporary privacy detector.

    This is a development implementation.
    Later, the AI/NLP teammate's context-aware model
    can replace or extend this detector.
    """

    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    PHONE_PATTERN = re.compile(
        r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b"
    )

    def detect(self, text: str) -> List[Dict]:
        detections = []

        # Detect email
        for match in self.EMAIL_PATTERN.finditer(text):
            detections.append({
                "entity_type": "EMAIL",
                "text": match.group(),
                "start": match.start(),
                "end": match.end(),
                "confidence": 0.99,
                "risk_level": "HIGH",
                "reason": "Detected as an email address.",
                "action": "REDACT"
            })

        # Detect phone number
        for match in self.PHONE_PATTERN.finditer(text):
            detections.append({
                "entity_type": "PHONE",
                "text": match.group(),
                "start": match.start(),
                "end": match.end(),
                "confidence": 0.98,
                "risk_level": "HIGH",
                "reason": "Detected as a phone number.",
                "action": "REDACT"
            })

        return detections