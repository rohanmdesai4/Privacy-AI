import re

def redact_text(text: str) -> str:
    # Hide email addresses
    text = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "[EMAIL REDACTED]",
        text,
    )

    # Hide 10-digit phone numbers
    text = re.sub(
        r"\b\d{10}\b",
        "[PHONE REDACTED]",
        text,
    )

    return text