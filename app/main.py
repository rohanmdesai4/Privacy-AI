from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re

app = FastAPI(
    title="PrivacyShield AI",
    version="0.1.0"
)

# --------------------------------------------------
# CORS
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# REQUEST MODEL
# --------------------------------------------------

class PrivacyRequest(BaseModel):
    text: str
    data_type: str = "workplace_text"


# --------------------------------------------------
# PRIVACY ANALYSIS
# --------------------------------------------------

def analyze_privacy(text: str):

    protected_text = text
    risks = []

    # -----------------------------
    # EMAIL DETECTION
    # -----------------------------

    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'

    emails = re.findall(email_pattern, text)

    if emails:
        protected_text = re.sub(
            email_pattern,
            "[EMAIL]",
            protected_text
        )

        risks.append({
            "type": "EMAIL",
            "description": "Email address detected",
            "severity": "HIGH"
        })


    # -----------------------------
    # PASSWORD / CREDENTIAL DETECTION
    # -----------------------------

    password_patterns = [
        r'(?i)(password\s*(is|=|:)\s*)([^\s,.;]+)',
        r'(?i)(passwd\s*(is|=|:)\s*)([^\s,.;]+)',
        r'(?i)(pwd\s*(is|=|:)\s*)([^\s,.;]+)'
    ]

    password_found = False

    for pattern in password_patterns:

        if re.search(pattern, protected_text):

            protected_text = re.sub(
                pattern,
                r'\1[CREDENTIAL]',
                protected_text
            )

            password_found = True


    if password_found:

        risks.append({
            "type": "CREDENTIAL",
            "description": "Password or credential detected",
            "severity": "CRITICAL"
        })


    # -----------------------------
    # PHONE NUMBER
    # -----------------------------

    phone_pattern = r'(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)'

    phones = re.findall(phone_pattern, text)

    if phones:

        protected_text = re.sub(
            phone_pattern,
            "[PHONE]",
            protected_text
        )

        risks.append({
            "type": "PHONE",
            "description": "Phone number detected",
            "severity": "HIGH"
        })


    # -----------------------------
    # CONFIDENTIAL BUSINESS DATA
    # -----------------------------

    confidential_keywords = [
        "confidential",
        "internal",
        "salary",
        "financial projection",
        "revenue",
        "profit",
        "business strategy",
        "private project",
        "internal project",
        "secret"
    ]

    lower_text = text.lower()

    found_confidential = []

    for keyword in confidential_keywords:

        if keyword in lower_text:
            found_confidential.append(keyword)


    if found_confidential:

        risks.append({
            "type": "CONFIDENTIAL_BUSINESS",
            "description": "Potentially confidential workplace/business information detected",
            "severity": "HIGH"
        })


    # -----------------------------
    # PRIVACY LEVEL
    # -----------------------------

    if any(risk["severity"] == "CRITICAL" for risk in risks):

        privacy_level = "CRITICAL"

    elif any(risk["severity"] == "HIGH" for risk in risks):

        privacy_level = "HIGH"

    elif risks:

        privacy_level = "MEDIUM"

    else:

        privacy_level = "LOW"


    return {
        "original_text": text,
        "processed_text": protected_text,
        "privacy_level": privacy_level,
        "risks": risks,
        "items_found": len(risks)
    }


# --------------------------------------------------
# ROOT
# --------------------------------------------------

@app.get("/")
def root():

    return {
        "message": "PrivacyShield AI Backend is running!"
    }


# --------------------------------------------------
# PRIVACY API
# --------------------------------------------------

@app.post("/privacy")
def process_privacy(request: PrivacyRequest):

    result = analyze_privacy(request.text)

    return result