"""Central configuration. Everything is env-overridable; nothing secret is hardcoded."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- Persistence -------------------------------------------------------
    # SQLite by default so the project runs with zero setup. Point this at
    # postgresql+psycopg://user:pass@host/db for a production-shaped run.
    database_url: str = Field(default=f"sqlite:///{BASE_DIR / 'data' / 'razorpay_agentic.db'}")

    # --- LLM ---------------------------------------------------------------
    anthropic_api_key: str | None = None
    llm_model: str = "claude-opus-4-8"
    llm_effort: str = "high"
    llm_max_tokens: int = 8000
    # When no API key is present the agents fall back to deterministic rule
    # engines. The pipeline still runs end-to-end -- it just stops explaining
    # itself in prose.
    llm_enabled: bool = True

    # --- Email -------------------------------------------------------------
    # DRY RUN IS THE DEFAULT. Nothing leaves this machine unless you set
    # smtp_enabled=true AND provide real credentials.
    smtp_enabled: bool = False
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True
    email_from: str = "disputes@razorpay-demo.local"
    outbox_dir: Path = BASE_DIR / "outbox"

    # --- Risk policy -------------------------------------------------------
    # Score bands (0-100). Tuned in app/agents/policy.py.
    auto_refund_below: float = 30.0
    auto_reject_above: float = 70.0
    # Hard guardrail: no matter how clean the signals look, money above this
    # never moves without a human. Fintech 101.
    manual_review_amount_paise: int = 5_000_000  # Rs. 50,000

    # --- API ---------------------------------------------------------------
    api_title: str = "Autonomous Dispute & Fraud Investigation System"
    api_version: str = "1.0.0"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    (BASE_DIR / "data").mkdir(exist_ok=True)
    settings.outbox_dir.mkdir(exist_ok=True)
    return settings
