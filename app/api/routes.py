from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.privacy import PrivacyRecordCreate, PrivacyRecordResponse
from app.services.privacy_service import (
    get_privacy_records,
    process_privacy_text
)

router = APIRouter()


@router.post("/privacy", response_model=PrivacyRecordResponse)
def create_privacy(
    record: PrivacyRecordCreate,
    db: Session = Depends(get_db)
):
    return process_privacy_text(db, record)


@router.get("/privacy", response_model=list[PrivacyRecordResponse])
def get_privacy(
    db: Session = Depends(get_db)
):
    return get_privacy_records(db)