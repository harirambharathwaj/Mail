from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

class Settings(BaseSettings):
    database_url: str = "sqlite:///./phishing.db"
    virustotal_api_key: str = ""
    google_safe_browsing_api_key: str = ""
    bert_model_path: str = "../artifacts/bert-phishing"
    xgb_model_path: str = "../artifacts/xgboost_phishing.joblib"
    xgb_scaler_path: str = "../artifacts/xgb_scaler.joblib"
    cors_origins: List[str] = ["http://localhost:5173"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
