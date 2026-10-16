from pydantic import BaseModel
from typing import Optional


class PrivacyRecordCreate(BaseModel):
    user_id: Optional[str] = None
    data_type: str
    original_text: Optional[str] = None
    processed_text: Optional[str] = None
    privacy_level: str = "low"


class PrivacyRecordResponse(PrivacyRecordCreate):
    id: int

    class Config:
        from_attributes = True