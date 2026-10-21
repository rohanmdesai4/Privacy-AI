from dataclasses import dataclass
from typing import Literal


RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

PrivacyAction = Literal[
    "ALLOW",
    "MASK",
    "REDACT",
    "TOKENIZE",
    "REVIEW",
]


@dataclass
class Detection:
    entity_type: str
    text: str
    start: int
    end: int
    confidence: float
    risk_level: RiskLevel
    reason: str
    recommended_action: PrivacyAction


@dataclass
class DetectionResult:
    detections: list[Detection]