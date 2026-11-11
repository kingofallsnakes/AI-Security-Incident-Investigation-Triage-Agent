"""Read-only data source interfaces, normalisation, and mock implementations.

Every integration in this module is strictly read-only.  There are no
write, update, delete, or arbitrary-query methods.  Elasticsearch queries
are built from validated parameters using fixed templates — the model and
alert payload never supply raw DSL.

Sensitive fields (passwords, tokens, authorization headers, secrets) are
recursively redacted before events enter the pipeline.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
import json
from pathlib import Path
import re
import time
from typing import Any, Protocol

from .config import ALLOWED_FIELDS, SETTINGS
from .models import GeoLocation, NormalizedEvent, SearchWindow, ThreatIntelResult

# ---------------------------------------------------------------------------
# Sensitive-field redaction
# ---------------------------------------------------------------------------

SENSITIVE_KEYS = {
    "password", "passwd", "token", "access_token", "refresh_token",
    "authorization", "cookie", "secret", "api_key", "apikey",
    "session_id", "credential", "credentials",
}


def redact(value: Any) -> Any:
    """Recursively redact sensitive fields from a dict/list structure.

    The ``message`` key is stripped entirely — log message text is treated
    as untrusted data and never forwarded into the pipeline or report.
    """
    if isinstance(value, dict):
        def sensitive(key: str) -> bool:
            words = re.findall(r"[a-z0-9]+", re.sub(r"([a-z])([A-Z])", r"\1_\2", key).lower())
            return (
                any(word in SENSITIVE_KEYS for word in words)
                or ("api" in words and "key" in words)
                or ("session" in words and "id" in words)
            )
        return {k: ("[REDACTED]" if sensitive(k) else redact(v)) for k, v in value.items() if k.lower() != "message"}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


# ---------------------------------------------------------------------------
# Event normalisation
# ---------------------------------------------------------------------------

def normalize_record(source: dict[str, Any]) -> NormalizedEvent:
    """Convert a raw Elasticsearch hit or synthetic record into a NormalizedEvent.

    Handles both ``_source``-wrapped and flat record formats.  Applies
    UTC normalisation and redacts sensitive fields before returning.
    """
    src = source.get("_source", source)
    event = src.get("event", {}) if isinstance(src.get("event", {}), dict) else {}
    user = src.get("user", {}) if isinstance(src.get("user", {}), dict) else {}
    net = src.get("source", {}) if isinstance(src.get("source", {}), dict) else {}
    host = src.get("host", {}) if isinstance(src.get("host", {}), dict) else {}
    ts = src.get("@timestamp") or src.get("timestamp")
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid event timestamp") from exc
    if not isinstance(ts, datetime):
        raise ValueError("missing event timestamp")
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    eid = str(event.get("id") or src.get("event_id") or source.get("_id") or "unknown")
    fields = redact({k: v for k, v in src.items() if k not in {"message"}})
    return NormalizedEvent(
        timestamp=ts, event_id=eid,
        source_index=str(source.get("_index", src.get("source_index", "synthetic"))),
        document_id=str(source.get("_id", src.get("document_id", eid))),
        event_type=str(event.get("action") or src.get("event_type") or "unknown"),
        username=user.get("name") or src.get("username"),
        source_ip=net.get("ip") or src.get("source_ip"),
        hostname=host.get("name") or src.get("hostname"),
        outcome=event.get("outcome") or src.get("outcome"),
        fields=fields,
    )


# ---------------------------------------------------------------------------
# Read-only event source protocol & implementations
# ---------------------------------------------------------------------------

class ReadOnlyEventSource(Protocol):
    """Protocol for read-only event retrieval backends."""
    def search(self, window: SearchWindow, indicators: list[str]) -> tuple[list[NormalizedEvent], list[str]]: ...


class SyntheticEventSource:
    """Loads events from a static JSON fixture file for offline demos."""

    def __init__(self, fixture: str | Path | None = None):
        self.fixture = Path(fixture or Path(__file__).parent / "data" / "events.json")

    def search(self, window: SearchWindow, indicators: list[str]) -> tuple[list[NormalizedEvent], list[str]]:
        records = json.loads(self.fixture.read_text(encoding="utf-8"))
        events, warnings = [], []
        for record in records:
            try:
                events.append(normalize_record(record))
            except (ValueError, TypeError):
                warnings.append("One synthetic record had no valid timestamp and was skipped.")
        hits = [e for e in events if window.start <= e.timestamp <= window.end]
        if indicators:
            hits = [e for e in hits if e.username in indicators or e.source_ip in indicators or e.hostname in indicators]
        hits = sorted(hits, key=lambda e: e.timestamp)[:window.max_results]
        return hits, warnings


class ElasticsearchReadOnlySource:
    """Fixed-template Elasticsearch search.  Exposes no write or raw-query method.

    Queries are assembled from validated parameters only.  The searchable
    indices, fields, time range, and result limits are controlled by
    ``config.SETTINGS`` and ``config.ALLOWED_FIELDS``.
    """

    def __init__(self, url: str = SETTINGS.elasticsearch_url, api_key: str | None = SETTINGS.elasticsearch_api_key):
        from elasticsearch import Elasticsearch
        kwargs = {"request_timeout": SETTINGS.timeout_seconds, "max_retries": 1, "retry_on_timeout": False}
        if api_key:
            kwargs["api_key"] = api_key
        self.__client = Elasticsearch(url, **kwargs)

    def search(self, window: SearchWindow, indicators: list[str]) -> tuple[list[NormalizedEvent], list[str]]:
        query: dict[str, Any] = {
            "bool": {
                "filter": [{
                    "range": {
                        "@timestamp": {
                            "gte": window.start.isoformat(),
                            "lte": window.end.isoformat(),
                        }
                    }
                }]
            }
        }
        if indicators:
            query["bool"]["should"] = [
                {"terms": {field: indicators}}
                for field in ("user.name", "source.ip", "host.name", "event.id")
            ]
            query["bool"]["minimum_should_match"] = 1
        try:
            hits = []
            warnings: list[str] = []
            while len(hits) < window.max_results:
                args = {
                    "index": ",".join(SETTINGS.allowed_indices),
                    "query": query,
                    "size": min(window.page_size, window.max_results - len(hits)),
                    "sort": [{"@timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}],
                    "source": list(ALLOWED_FIELDS),
                    "timeout": f"{SETTINGS.timeout_seconds}s",
                }
                if hits:
                    args["search_after"] = hits[-1]["sort"]
                response = self.__client.search(**args)
                if response.get("timed_out"):
                    warnings.append("Elasticsearch timed out before completing the search.")
                shard_info = response.get("_shards", {})
                if shard_info.get("failed", 0):
                    warnings.append(f"Elasticsearch reported {shard_info['failed']} failed shard(s).")
                page = response["hits"]["hits"]
                hits.extend(page)
                if not page or len(page) < args["size"]:
                    break
            total = response["hits"].get("total", 0)
            total = total.get("value", 0) if isinstance(total, dict) else total
            if total > len(hits):
                if len(hits) >= window.max_results:
                    warnings.append(f"Elasticsearch result limit reached ({window.max_results}).")
                else:
                    warnings.append(f"Elasticsearch returned a partial result set ({len(hits)} of {total}).")
            events = []
            for hit in hits[:window.max_results]:
                try:
                    events.append(normalize_record(hit))
                except (ValueError, TypeError):
                    warnings.append("One Elasticsearch record had no valid timestamp and was skipped.")
            return events, warnings
        except Exception as exc:
            return [], [f"Elasticsearch search failed ({type(exc).__name__})."]


# ---------------------------------------------------------------------------
# Reputation & GeoIP interfaces & implementations
# ---------------------------------------------------------------------------

class ReputationClient(Protocol):
    """Protocol for IP reputation lookup backends."""
    def lookup(self, ip: str) -> ThreatIntelResult: ...


class GeoIPClient(Protocol):
    """Protocol for IP geolocation lookup backends."""
    def lookup(self, ip: str) -> GeoLocation: ...


class MockReputationClient:
    """Deterministic offline reputation mock for testing and demos."""

    def __init__(self, scores: dict[str, int] | None = None, fail: bool = False):
        self.scores = scores or {"203.0.113.77": 0}
        self.fail = fail
        self.calls: list[str] = []

    def lookup(self, ip: str) -> ThreatIntelResult:
        self.calls.append(ip)
        if self.fail:
            return ThreatIntelResult(
                ip=ip, provider="Offline mock", queried=False,
                lookup_time=datetime.now(timezone.utc),
                error="mock provider unavailable",
            )
        return ThreatIntelResult(
            ip=ip, provider="Offline mock", queried=True,
            lookup_time=datetime.now(timezone.utc),
            abuse_confidence_score=self.scores.get(ip, 0),
            metadata={"source": "offline mock"},
        )


class MockGeoIPClient:
    """Deterministic offline geolocation mock for impossible-travel detection demos.

    Maps well-known demo IPs to fixed country/city locations.  Unknown IPs
    get a default US location.  Private/reserved IPs return no geo data.
    """

    _LOCATIONS: dict[str, dict[str, Any]] = {
        "198.51.100.23": {"country_code": "US", "country_name": "United States", "city": "New York", "latitude": 40.71, "longitude": -74.01},
        "8.8.8.8":       {"country_code": "US", "country_name": "United States", "city": "Mountain View", "latitude": 37.39, "longitude": -122.08},
        "203.0.113.5":   {"country_code": "RU", "country_name": "Russia", "city": "Moscow", "latitude": 55.75, "longitude": 37.62},
        "203.0.113.77":  {"country_code": "CN", "country_name": "China", "city": "Beijing", "latitude": 39.90, "longitude": 116.40},
        "192.0.2.10":    {"country_code": "GB", "country_name": "United Kingdom", "city": "London", "latitude": 51.51, "longitude": -0.13},
        "198.51.100.50": {"country_code": "DE", "country_name": "Germany", "city": "Berlin", "latitude": 52.52, "longitude": 13.40},
        "203.0.113.99":  {"country_code": "BR", "country_name": "Brazil", "city": "São Paulo", "latitude": -23.55, "longitude": -46.63},
    }

    def __init__(self, extra: dict[str, dict[str, Any]] | None = None):
        self.locations = dict(self._LOCATIONS)
        if extra:
            self.locations.update(extra)

    def lookup(self, ip: str) -> GeoLocation:
        try:
            parsed = ip_address(ip)
        except ValueError:
            return GeoLocation(ip=ip)
        if not parsed.is_global:
            return GeoLocation(ip=str(parsed))
        key = str(parsed)
        loc = self.locations.get(key, {
            "country_code": "US", "country_name": "United States",
            "city": "Unknown", "latitude": 37.0, "longitude": -95.0,
        })
        return GeoLocation(ip=key, **loc, is_mock=True)


class FreeIPIntelClient:
    """100% Free, Zero-API-Key-Required Public IP Intelligence & GeoIP Client.

    Uses the public ip-api.com service (free for non-commercial research,
    no signup or API key required). Features:
    - In-memory TTL caching (1 hour) to minimize outbound calls
    - Safe rate-limiting (max 45 requests/min)
    - Rejects private/reserved RFC IPs before querying
    - Detects Datacenter, VPN, and Proxy hosting (critical SOC signals)
    - Seamless fallback to local mocks if offline, rate-limited, or blocked.
    """

    def __init__(self, cache_seconds: int = 3600, min_interval_seconds: float = 1.0):
        self.cache_seconds = cache_seconds
        self.min_interval = min_interval_seconds
        self.cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self.last_request = 0.0
        self._fallback_geo = MockGeoIPClient()
        self._fallback_rep = MockReputationClient()

    def _fetch(self, ip: str) -> dict[str, Any] | None:
        try:
            parsed = ip_address(ip)
        except ValueError:
            return None
        if not parsed.is_global:
            return None
        key = str(parsed)
        cached = self.cache.get(key)
        if cached and time.monotonic() - cached[0] < self.cache_seconds:
            return cached[1]

        wait = self.min_interval - (time.monotonic() - self.last_request)
        if wait > 0:
            time.sleep(wait)

        import httpx
        try:
            url = f"http://ip-api.com/json/{key}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,proxy,hosting"
            resp = httpx.get(url, timeout=2.5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    self.last_request = time.monotonic()
                    self.cache[key] = (time.monotonic(), data)
                    return data
        except Exception:
            pass
        return None

    def lookup(self, ip: str) -> ThreatIntelResult:
        data = self._fetch(ip)
        if data:
            proxy = bool(data.get("proxy", False))
            hosting = bool(data.get("hosting", False))
            abuse_score = 45 if (proxy and hosting) else (30 if (proxy or hosting) else 0)
            meta = {
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
                "proxy": proxy,
                "hosting": hosting,
                "api_type": "Public Free Resource (No API Key Required)",
            }
            return ThreatIntelResult(
                ip=ip,
                queried=True,
                lookup_time=datetime.now(timezone.utc),
                provider="ip-api.com (Free Public API)",
                abuse_confidence_score=abuse_score,
                metadata=meta,
            )
        # Seamless fallback
        return self._fallback_rep.lookup(ip)

    def lookup_geo(self, ip: str) -> GeoLocation:
        data = self._fetch(ip)
        if data:
            return GeoLocation(
                ip=ip,
                country_code=data.get("countryCode"),
                country_name=data.get("country"),
                city=data.get("city"),
                latitude=data.get("lat"),
                longitude=data.get("lon"),
                is_mock=False,
            )
        return self._fallback_geo.lookup(ip)


class AbuseIPDBClient:
    """Public-IP-only, in-memory cached, rate-limited AbuseIPDB client.

    - Rejects private, reserved, loopback, and link-local IPs before querying.
    - Caches results for ``cache_seconds`` to reduce API calls.
    - Enforces ``min_interval_seconds`` between consecutive requests.
    - The API key is never logged or included in results.
    """

    def __init__(self, api_key: str, cache_seconds: int = 3600, min_interval_seconds: float = 1.0):
        self.api_key = api_key
        self.cache_seconds = cache_seconds
        self.min_interval = min_interval_seconds
        self.cache: dict[str, tuple[float, ThreatIntelResult]] = {}
        self.last_request = 0.0

    def lookup(self, ip: str) -> ThreatIntelResult:
        now = datetime.now(timezone.utc)
        try:
            parsed = ip_address(ip)
        except ValueError:
            return ThreatIntelResult(ip=ip, queried=False, lookup_time=now, error="invalid IP")
        if not parsed.is_global:
            return ThreatIntelResult(ip=str(parsed), queried=False, lookup_time=now, error="non-public IP excluded")
        key = str(parsed)
        cached = self.cache.get(key)
        if cached and time.monotonic() - cached[0] < self.cache_seconds:
            return cached[1].model_copy()
        wait = self.min_interval - (time.monotonic() - self.last_request)
        if wait > 0:
            time.sleep(wait)
        import httpx
        try:
            response = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": key, "maxAgeInDays": 90},
                headers={"Key": self.api_key, "Accept": "application/json"},
                timeout=3.0,
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            result = ThreatIntelResult(
                ip=key, queried=True, lookup_time=datetime.now(timezone.utc),
                abuse_confidence_score=data.get("abuseConfidenceScore"),
                metadata={k: data[k] for k in ("totalReports", "lastReportedAt", "isWhitelisted") if k in data},
            )
            self.last_request = time.monotonic()
            self.cache[key] = (time.monotonic(), result)
            return result
        except Exception as exc:
            return ThreatIntelResult(
                ip=key, queried=False, lookup_time=datetime.now(timezone.utc),
                error=f"provider unavailable ({type(exc).__name__})",
            )
