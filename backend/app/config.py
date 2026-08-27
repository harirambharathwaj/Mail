from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

BASE_DIR = Path(__file__).resolve().parent.parent.parent
ARTIFACTS_DIR = BASE_DIR / "artifacts"

class Settings(BaseSettings):
    database_url: str = "sqlite:///./phishing.db"
    virustotal_api_key: str = ""
    google_safe_browsing_api_key: str = ""
    bert_model_path: str = str(ARTIFACTS_DIR / "bert-phishing")
    xgb_model_path: str = str(ARTIFACTS_DIR / "xgboost_phishing.joblib")
    xgb_scaler_path: str = str(ARTIFACTS_DIR / "xgb_scaler.joblib")
    cors_origins: List[str] = ["http://localhost:5173"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
