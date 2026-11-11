"""Validated Pydantic models for alerts, evidence, findings, and investigation reports.

Every model uses ``extra="forbid"`` to reject unexpected fields and prevent
alert payloads from injecting arbitrary query controls.  Timestamps are
coerced to UTC on construction.  The ``RecommendedAction.advisory_only``
field is typed as ``Literal[True]`` so a non-True value is a schema violation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_address
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Alert / recommended severity levels."""
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class InvestigationStatus(str, Enum):
    """Machine-readable investigation lifecycle status."""
    queued = "queued"
    running = "running"
    completed = "completed"
    completed_with_warnings = "completed_with_warnings"


# ---------------------------------------------------------------------------
# Indicator & Alert Input
# ---------------------------------------------------------------------------

class Indicator(BaseModel):
    """A single observable extracted from an alert or enrichment step."""
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(pattern=r"^(ip|username|hostname|event_id|entity)$")
    value: str = Field(min_length=1, max_length=255)
    source: str = Field(default="alert", max_length=100)
    context: str = Field(default="", max_length=500)


class AlertInput(BaseModel):
    """Validated alert payload accepted by the investigation API.

    - ``extra="forbid"`` blocks injection of raw queries or unknown fields.
    - Naive (timezone-unaware) timestamps are rejected.
    - Timestamps are normalised to UTC on construction.
    """
    model_config = ConfigDict(extra="forbid")
    incident_id: str = Field(
        default_factory=lambda: f"INC-{uuid4().hex[:12]}",
        pattern=r"^[A-Za-z0-9_-]{3,64}$",
    )
    source: str = Field(min_length=1, max_length=100)
    severity: Severity
    timestamp: datetime
    affected_user: str | None = Field(default=None, max_length=128)
    affected_host: str | None = Field(default=None, max_length=255)
    indicators: list[Indicator] = Field(default_factory=list, max_length=50)
    description: str = Field(default="", max_length=2000)

    @field_validator("timestamp")
    @classmethod
    def utc_timestamp(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        return v.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Search & Evidence
# ---------------------------------------------------------------------------

class SearchWindow(BaseModel):
    """Bounded time range for log queries.

    Enforces an ordered, timezone-aware window no wider than 26 hours with
    hard limits on result count and page size.
    """
    start: datetime
    end: datetime
    max_results: int = Field(ge=1, le=500)
    page_size: int = Field(ge=1, le=100)

    @model_validator(mode="after")
    def bounded_window(self):
        if self.start.tzinfo is None or self.end.tzinfo is None or self.end <= self.start:
            raise ValueError("search window must be ordered and timezone-aware")
        if (self.end - self.start).total_seconds() > 26 * 3600:
            raise ValueError("search window cannot exceed 26 hours")
        return self


class NormalizedEvent(BaseModel):
    """A single log record normalised into a common event model.

    Carries full provenance (``source_index``, ``document_id``, ``event_id``)
    so every downstream reference is traceable to the original record.
    """
    timestamp: datetime
    event_id: str
    source_index: str
    document_id: str
    event_type: str = "unknown"
    username: str | None = None
    source_ip: str | None = None
    hostname: str | None = None
    outcome: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def event_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("event timestamp must include timezone")
        return v.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Threat Intelligence & GeoIP
# ---------------------------------------------------------------------------

class ThreatIntelResult(BaseModel):
    """Result of a single IP reputation lookup (e.g. AbuseIPDB)."""
    ip: str
    queried: bool
    lookup_time: datetime
    provider: str = "AbuseIPDB"
    abuse_confidence_score: int | None = Field(default=None, ge=0, le=100)
    metadata: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class GeoLocation(BaseModel):
    """Geographic attribution for an IP address.

    Used for impossible-travel detection.  In offline mode all results
    come from a deterministic mock and ``is_mock`` is always True.
    """
    ip: str
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    is_mock: bool = True


# ---------------------------------------------------------------------------
# MITRE ATT&CK Mapping
# ---------------------------------------------------------------------------

class MitreMapping(BaseModel):
    """Maps a finding to a MITRE ATT&CK technique and tactic.

    Reference URLs point to the public ATT&CK knowledge base.
    """
    technique_id: str        # e.g. "T1110"
    technique_name: str      # e.g. "Brute Force"
    tactic: str              # e.g. "Credential Access"
    reference_url: str       # e.g. "https://attack.mitre.org/techniques/T1110/"


# ---------------------------------------------------------------------------
# Risk Scoring
# ---------------------------------------------------------------------------

class RiskScoreComponent(BaseModel):
    """One weighted factor that contributes to the composite risk score."""
    factor: str
    score: float = Field(ge=0, le=100)
    weight: float = Field(ge=0, le=1.0)
    explanation: str


class RiskScore(BaseModel):
    """Composite risk assessment with transparent component breakdown.

    ``overall`` is the weighted sum of component scores, capped at 100.
    """
    overall: float = Field(ge=0, le=100)
    components: list[RiskScoreComponent] = Field(default_factory=list)
    explanation: str = ""


# ---------------------------------------------------------------------------
# Timeline, Findings, and Actions
# ---------------------------------------------------------------------------

class TimelineEntry(BaseModel):
    """A single point on the reconstructed investigation timeline."""
    timestamp: datetime
    summary: str
    evidence_refs: list[str] = Field(min_length=1)
    uncertainty: str | None = None


class Finding(BaseModel):
    """An analytical finding with evidence citations and optional MITRE mapping."""
    title: str
    observed_facts: list[str] = Field(default_factory=list)
    inference: str | None = None
    evidence_refs: list[str] = Field(min_length=1)
    contradictory_evidence: list[str] = Field(default_factory=list)
    mitre_mappings: list[MitreMapping] = Field(default_factory=list)


class RecommendedAction(BaseModel):
    """A human-supervised advisory response procedure.

    ``advisory_only`` is typed as ``Literal[True]`` — any attempt to set
    it to False is rejected at validation time.
    """
    description: str
    rationale: str
    urgency: str = Field(pattern=r"^(low|medium|high|immediate)$")
    required_human_role: str
    validation_checks: list[str] = Field(default_factory=list)
    advisory_only: Literal[True] = True


# ---------------------------------------------------------------------------
# Investigation Report
# ---------------------------------------------------------------------------

class InvestigationReport(BaseModel):
    """The complete, structured investigation brief returned by the pipeline.

    Includes the alert, search parameters, retrieved evidence, enrichment
    results, analytical findings, timeline, risk score, recommendations,
    and a full audit trail.
    """
    incident_id: str
    status: InvestigationStatus
    started_at: datetime
    completed_at: datetime
    alert: AlertInput
    search_window: SearchWindow
    data_sources_queried: list[str]
    events: list[NormalizedEvent]
    indicators: list[Indicator]
    enrichment_results: list[ThreatIntelResult]
    geo_locations: list[GeoLocation] = Field(default_factory=list)
    timeline: list[TimelineEntry]
    findings: list[Finding]
    risk_score: RiskScore | None = None
    recommended_severity: Severity
    severity_rationale: str
    confidence: str
    confidence_limits: list[str]
    unknowns: list[str]
    recommended_actions: list[RecommendedAction]
    warnings: list[str] = Field(default_factory=list)
    audit: list[dict[str, Any]] = Field(default_factory=list)
    markdown_summary: str


# ---------------------------------------------------------------------------
# Indicator normalisation helper
# ---------------------------------------------------------------------------

def normalize_indicators(alert: AlertInput) -> list[Indicator]:
    """Extract, validate, normalise, and deduplicate indicators from an alert.

    - IP addresses are parsed and canonicalised.
    - Invalid IPs are silently dropped.
    - Usernames and hostnames are lowercased.
    - Duplicates (by kind + normalised value) are removed.
    """
    items = list(alert.indicators)
    if alert.affected_user:
        items.append(Indicator(kind="username", value=alert.affected_user, source="alert.affected_user"))
    if alert.affected_host:
        items.append(Indicator(kind="hostname", value=alert.affected_host, source="alert.affected_host"))
    output: list[Indicator] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        value = item.value.strip()
        kind = item.kind
        if kind == "ip":
            try:
                value = str(ip_address(value))
            except ValueError:
                continue
        elif kind in {"username", "hostname", "event_id"}:
            value = value.lower()
        key = (kind, value)
        if value and key not in seen:
            seen.add(key)
            output.append(item.model_copy(update={"value": value}))
    return output
