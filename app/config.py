from dataclasses import dataclass
import os
from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    mode: str = os.getenv("APP_MODE", "offline")
    elasticsearch_url: str = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
    elasticsearch_api_key: str | None = os.getenv("ELASTICSEARCH_API_KEY") or None
    abuseipdb_api_key: str | None = os.getenv("ABUSEIPDB_API_KEY") or None
    lookback_hours: int = min(24, max(1, int(os.getenv("LOOKBACK_HOURS", "24"))))
    lookahead_hours: int = min(2, max(0, int(os.getenv("LOOKAHEAD_HOURS", "2"))))
    max_events: int = min(500, max(1, int(os.getenv("MAX_EVENTS", "500"))))
    page_size: int = min(100, max(1, int(os.getenv("PAGE_SIZE", "100"))))
    timeout_seconds: float = min(5.0, max(0.5, float(os.getenv("SEARCH_TIMEOUT_SECONDS", "5"))))
    allowed_indices: tuple[str, ...] = ("auth-logs", "endpoint-logs", "server-logs")


SETTINGS = Settings()
ALLOWED_FIELDS = ("@timestamp", "event.id", "event.action", "user.name", "source.ip", "host.name", "event.outcome", "message")
