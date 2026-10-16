from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime

from app.db.database import Base


class PrivacyRecord(Base):
    __tablename__ = "privacy_records"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(String(100), nullable=True, index=True)

    data_type = Column(String(100), nullable=False)

    original_text = Column(Text, nullable=True)

    processed_text = Column(Text, nullable=True)

    privacy_level = Column(String(50), default="low")

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )