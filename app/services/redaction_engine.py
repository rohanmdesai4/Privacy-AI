from typing import List, Dict


class RedactionEngine:

    def redact(
        self,
        text: str,
        detections: List[Dict]
    ) -> str:

        if not detections:
            return text

        # Process from right to left so that
        # replacing one entity does not change
        # the positions of entities before it.
        sorted_detections = sorted(
            detections,
            key=lambda item: item["start"],
            reverse=True
        )

        sanitized_text = text

        counters = {}

        for detection in sorted_detections:

            entity_type = detection["entity_type"]

            if entity_type == "EMAIL":
                replacement = "[REDACTED_EMAIL]"

            elif entity_type == "PHONE":
                replacement = "[REDACTED_PHONE]"

            else:
                count = counters.get(entity_type, 0) + 1
                counters[entity_type] = count
                replacement = f"[{entity_type}_{count}]"

            start = detection["start"]
            end = detection["end"]

            sanitized_text = (
                sanitized_text[:start]
                + replacement
                + sanitized_text[end:]
            )

        return sanitized_text