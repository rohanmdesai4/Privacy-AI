class RedactionEngine:
    """
    Redaction engine for the Context-Aware Data Privacy system.

    Takes detections produced by PrivacyDetector and replaces
    sensitive text with safe labels such as:
        [PERSON]
        [EMAIL]
        [PHONE]
        [FINANCIAL_INFORMATION]
        [CONFIDENTIAL_INFORMATION]
        [CREDENTIAL]
    """

    def __init__(self):
        self.default_replacement = "[REDACTED]"

    def redact(self, text, detections):
        """
        Redact sensitive portions of text.

        Parameters:
            text (str): Original workplace text.
            detections (list): List of detection dictionaries.

        Returns:
            str: Redacted/processed text.
        """

        # Nothing to redact
        if not text:
            return text

        if not detections:
            return text

        processed_text = text

        # Process from right to left.
        # This prevents changing the indexes of earlier detections.
        valid_detections = [
            detection
            for detection in detections
            if isinstance(detection, dict)
            and "start" in detection
            and "end" in detection
        ]

        valid_detections.sort(
            key=lambda detection: detection["start"],
            reverse=True
        )

        for detection in valid_detections:

            start = detection["start"]
            end = detection["end"]

            # Make sure indexes are valid
            if not isinstance(start, int) or not isinstance(end, int):
                continue

            if start < 0 or end > len(processed_text) or start >= end:
                continue

            # Get entity type
            entity_type = detection.get(
                "entity_type",
                "REDACTED"
            )

            # Create replacement label
            replacement = f"[{entity_type}]"

            # Replace sensitive text
            processed_text = (
                processed_text[:start]
                + replacement
                + processed_text[end:]
            )

        return processed_text


# ---------------------------------------------------------
# GLOBAL REDACTION ENGINE INSTANCE
# ---------------------------------------------------------
# privacy_service.py imports this object using:
#
# from app.services.redaction_engine import redactor
#
# Therefore this variable MUST be named "redactor".

redactor = RedactionEngine()