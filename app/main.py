from fastapi import FastAPI

from app.api.routes import router
from app.db.database import Base, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Context-Aware Data Privacy API",
    description="Backend API for detecting and protecting sensitive workplace information",
    version="0.1.0"
)

app.include_router(router)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "context-aware-data-privacy"
    }