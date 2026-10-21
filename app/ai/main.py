from fastapi import FastAPI
from pydantic import BaseModel

from app.services.detector import detect_sensitive_information
from app.services.redaction_engine import RedactionEngine

app = FastAPI(
    title="Privacy AI API",
    description="Context-aware sensitive information detection",
    version="1.0.0",
)


class ScanRequest(BaseModel):
    text: str


@app.get("/")
def home():
    return {"message": "Privacy AI API is running"}


@app.post("/scan")
def scan_text(request: ScanRequest):
    result = detect_sensitive_information(request.text)

    redaction_engine = RedactionEngine()
    redacted_text = redaction_engine.redact(request.text)

    return {
        "detections": result.detections,
        "redacted_text": redacted_text
    }

    
    