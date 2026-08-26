from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api.router import api_router
from app.database import engine, Base
import app.models  # noqa: F401
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure all database schema tables exist on startup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # Shutdown actions

app = FastAPI(title="Email Threat Intel API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

@app.get("/")
async def root():
    return {
        "message": "Email Threat Intel API",
        "docs": "/docs",
        "health": "/api/health",
        "status": "online"
    }

@app.get("/api/health")
async def health_check():
    return {"status": "ok"}

