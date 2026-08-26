from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

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
    
    NLP_MODEL_PATH: str = "ml/models/nlp_classifier"
    ENSEMBLE_MODEL_PATH: str = "ml/models/ensemble_meta.joblib"
    
    CORS_ORIGINS: List[str] = ["http://localhost:5173"]
    
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
