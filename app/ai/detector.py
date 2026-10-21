import re

from src.schemas import Detection, DetectionResult


EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

PHONE_PATTERN = re.compile(
    r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)"
)

MONEY_PATTERN = re.compile(
    r"(?:₹|Rs\.?|INR|\$)\s*\d[\d,]*(?:\.\d+)?"
)

FINANCIAL_CONTEXT = (
    "revenue projection",
    "revenue forecast",
    "financial projection",
    "profit forecast",
    "budget forecast",
    "projected revenue",
    "confidential financial",
    "expected sales",
    "sales forecast",
    "sales projection",
    "expects sales",
    "expects revenue",
    "annual revenue",
    "quarterly revenue",
    "future earnings",
    "earnings forecast",
    "projected profit",
    "internal budget",
    "financial outlook",

)


def detect_sensitive_information(text: str) -> DetectionResult:
    detections = []

    def add_detection(
        match,
        entity_type,
        risk_level,
        reason,
        action,
        confidence=0.95,
    ):
        detections.append(
            Detection(
                entity_type=entity_type,
                text=match.group(),
                start=match.start(),
                end=match.end(),
                confidence=confidence,
                risk_level=risk_level,
                reason=reason,
                recommended_action=action,
            )
        )

    # Detect email addresses.
    for match in EMAIL_PATTERN.finditer(text):
        add_detection(
            match,
            "EMAIL",
            "HIGH",
            "Email address detected.",
            "REDACT",
        )

    # Detect likely phone numbers. Ignore short digit sequences.
    for match in PHONE_PATTERN.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        if 10 <= len(digits) <= 15:
            add_detection(
                match,
                "PHONE",
                "HIGH",
                "Possible phone number detected.",
                "REDACT",
                confidence=0.80,
            )

    # Detect money amounts only when financial context is present.
    lowered_text = text.lower()
    has_financial_context = any(
        phrase in lowered_text for phrase in FINANCIAL_CONTEXT
    )

    if has_financial_context:
        for match in MONEY_PATTERN.finditer(text):
            add_detection(
                match,
                "FINANCIAL_PROJECTION",
                "HIGH",
                "Money amount appears in a financial projection context.",
                "REDACT",
                confidence=0.85,
            )

    # Remove duplicate detections and keep source order.
    unique = {
        (d.entity_type, d.start, d.end): d
        for d in detections
    }

    return DetectionResult(
        detections=sorted(unique.values(), key=lambda d: d.start)
    )