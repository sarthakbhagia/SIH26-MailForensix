import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional


def _resolve_default_path(rel_path: str) -> str:
    """Resolve relative model paths against cwd, backend dir, or repo root."""
    p = Path(rel_path)
    if p.exists():
        return str(p)
    backend_dir = Path(__file__).resolve().parent.parent
    p_backend = backend_dir / rel_path
    if p_backend.exists():
        return str(p_backend)
    repo_root = backend_dir.parent
    p_repo = repo_root / rel_path
    if p_repo.exists():
        return str(p_repo)
    return rel_path


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/email_threat_intel"
    REDIS_URL: str = "redis://localhost:6379/0"
    MAXMIND_DB_PATH: str = "data/GeoLite2-City.mmdb"
    ABUSEIPDB_KEY: str = ""
    VIRUSTOTAL_KEY: str = ""
    IPINFO_TOKEN: str = ""
    
    ALERT_THRESHOLD_HIGH: int = 75
    ALERT_THRESHOLD_CRITICAL: int = 90
    
    RISK_WEIGHT_NLP: float = 0.35
    RISK_WEIGHT_AUTH: float = 0.25
    RISK_WEIGHT_IP: float = 0.20
    RISK_WEIGHT_GEO: float = 0.10
    RISK_WEIGHT_LINK: float = 0.10
    
    # Model artifact paths
    NLP_MODEL_PATH: Optional[str] = _resolve_default_path("ml/models/nlp_classifier")
    ENSEMBLE_MODEL_PATH: Optional[str] = _resolve_default_path("ml/models/ensemble_meta.joblib")
    TABULAR_MODEL_PATH: Optional[str] = _resolve_default_path("ml/models/tabular_classifier.joblib")
    
    # JWT Authentication
    JWT_SECRET_KEY: str = "kcQITBywHmUx8DWP9ZXMpjgbwl6M67abpSwWLAmCUwJ"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60
    
    CORS_ORIGINS: List[str] = ["http://localhost:5173"]
    
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()

