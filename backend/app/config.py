from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]

class Settings(BaseSettings):
    app_name: str = "DDoS Attack Detection // SOC Engine"
    environment: str = "development"
    api_key: str = ""
    require_trained_model: bool = False
    database_url: str = ""
    redis_url: str = ""
    prometheus_enabled: bool = True
    drift_window: int = 250
    drift_z_threshold: float = 4.0
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8080"
    database_path: str = str(ROOT / "data" / "ddos.sqlite3")
    model_path: str = str(ROOT / "models" / "ddos_detector.joblib")
    model_version: str = "untrained"
    random_seed: int = 42
    demo_interval_ms: int = 350
    alert_threshold: float = 0.78
    critical_threshold: float = 0.94
    max_events: int = 5000
    model_sample_rows: int = 500000
    model_test_size: float = 0.20
    model_min_roc_auc: float = 0.90
    model_min_recall: float = 0.90
    replay_dir: str = str(ROOT / "data" / "processed")
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

@lru_cache
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
