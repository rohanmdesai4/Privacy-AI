from sqlalchemy.orm import Session

from app.models.privacy import PrivacyRecord
from app.schemas.privacy import PrivacyRecordCreate

from app.services.detector import PrivacyDetector
from app.services.redaction_engine import RedactionEngine


# Create detector and redaction engine
detector = PrivacyDetector()
redactor = RedactionEngine()


# ============================================================
# GET ALL PRIVACY RECORDS
# ============================================================

def get_privacy_records(db: Session):
    return db.query(PrivacyRecord).all()


# ============================================================
# PROCESS PRIVACY TEXT
# ============================================================

def process_privacy_text(
    db: Session,
    record: PrivacyRecordCreate
):
    """
    Detect sensitive information,
    redact it,
    calculate privacy level,
    save the result to database,
    and return the saved record.
    """

    # --------------------------------------------------------
    # STEP 1: Detect sensitive information
    # --------------------------------------------------------

    detections = detector.detect(
        record.original_text
    )

    # --------------------------------------------------------
    # STEP 2: Redact detected information
    # --------------------------------------------------------

    processed_text = redactor.redact(
        record.original_text,
        detections
    )

    # --------------------------------------------------------
    # STEP 3: Calculate privacy level
    # --------------------------------------------------------

    if not detections:
        privacy_level = "LOW"

    elif any(
        detection.get("risk_level") == "HIGH"
        for detection in detections
    ):
        privacy_level = "HIGH"

    else:
        privacy_level = "MEDIUM"

    # --------------------------------------------------------
    # STEP 4: Create database record
    # --------------------------------------------------------

    db_record = PrivacyRecord(
        user_id=record.user_id,
        data_type=record.data_type,
        original_text=record.original_text,
        processed_text=processed_text,
        privacy_level=privacy_level
    )

    # --------------------------------------------------------
    # STEP 5: Save record
    # --------------------------------------------------------

    db.add(db_record)
    db.commit()

    # --------------------------------------------------------
    # STEP 6: Refresh database object
    # --------------------------------------------------------

    db.refresh(db_record)

    # --------------------------------------------------------
    # STEP 7: Return result
    # --------------------------------------------------------

    return db_record