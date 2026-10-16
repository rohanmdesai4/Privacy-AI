from sqlalchemy.orm import Session

from app.models.privacy import PrivacyRecord
from pytest import Session


from app.schemas.privacy import PrivacyRecordCreate

from app.services.detector import PrivacyDetector
from app.services.redaction_engine import RedactionEngine


detector = PrivacyDetector()
redactor = RedactionEngine()


def create_privacy_record(
    db: Session,
    record: PrivacyRecordCreate
):
    db_record = PrivacyRecord(
        user_id=record.user_id,
        data_type=record.data_type,
        original_text=record.original_text,
        processed_text=record.processed_text,
        privacy_level=record.privacy_level,
    )

    db.add(db_record)
    db.commit()
    db.refresh(db_record)

    return db_record


def get_privacy_records(
    db: Session
):
    return db.query(PrivacyRecord).all()

def process_privacy_text(
    db: Session,
    record: PrivacyRecordCreate
):
    detections = detector.detect(record.original_text)

    processed_text = redactor.redact(
        record.original_text,
        detections
    )

    record.processed_text = processed_text

    return create_privacy_record(db, record)