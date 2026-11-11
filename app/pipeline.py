from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Any

from .config import ALLOWED_FIELDS, SETTINGS
from .models import (
    AlertInput,
    Finding,
    GeoLocation,
    Indicator,
    InvestigationReport,
    InvestigationStatus,
    MitreMapping,
    NormalizedEvent,
    RecommendedAction,
    RiskScore,
    RiskScoreComponent,
    SearchWindow,
    Severity,
    ThreatIntelResult,
    TimelineEntry,
    normalize_indicators,
)
from .sources import (
    AbuseIPDBClient,
    FreeIPIntelClient,
    GeoIPClient,
    MockGeoIPClient,
    MockReputationClient,
    ReadOnlyEventSource,
    ElasticsearchReadOnlySource,
    SyntheticEventSource,
)


def _public_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ip_address(value).is_global
    except ValueError:
        return False


def _calculate_risk_score(
    alert: AlertInput,
    events: list[NormalizedEvent],
    sequence: bool,
    intel: list[ThreatIntelResult],
    spray_detected: bool,
    multi_host: bool,
) -> RiskScore:
    """Compute a transparent, component-weighted composite risk score (0-100)."""
    # 1. Authentication Anomaly factor (weight 0.35)
    auth_events = [e for e in events if (e.event_type or "").lower() in {"login", "authentication", "auth", "user_login"}]
    fails = [e for e in auth_events if (e.outcome or "").lower() in {"failure", "failed", "deny"}]
    if sequence:
        auth_score = 85.0
        auth_expl = "Multiple authentication failures followed by successful login for the same user."
    elif len(fails) > 0:
        auth_score = min(70.0, 30.0 + len(fails) * 10.0)
        auth_expl = f"Observed {len(fails)} failed authentication attempts without verified success."
    elif auth_events:
        auth_score = 20.0
        auth_expl = "Routine successful authentication observed."
    else:
        auth_score = 10.0
        auth_expl = "No direct authentication events identified in the search window."

    # 2. Threat Intelligence factor (weight 0.25)
    max_abuse = max([r.abuse_confidence_score or 0 for r in intel], default=0)
    if max_abuse > 50:
        threat_score = float(max_abuse)
        threat_expl = f"High AbuseIPDB reputation score detected ({max_abuse}/100)."
    elif max_abuse > 0:
        threat_score = float(max_abuse)
        threat_expl = f"Low-to-moderate reputation score detected ({max_abuse}/100)."
    elif intel:
        threat_score = 10.0
        threat_expl = "Target public IP(s) evaluated with zero prior abuse reports."
    else:
        threat_score = 15.0
        threat_expl = "No public IPs required external threat intelligence enrichment."

    # 3. Asset & Identity Impact factor (weight 0.20)
    asset_score = 40.0
    asset_expl = "Standard user identity and endpoint telemetry in scope."
    if alert.affected_user:
        asset_score += 15.0
        asset_expl = f"Specific identity target identified: {alert.affected_user}."
    if alert.affected_host:
        asset_score += 10.0

    # 4. Scope & Lateral Movement factor (weight 0.20)
    if spray_detected:
        scope_score = 85.0
        scope_expl = "Potential credential spray observed spanning multiple accounts."
    elif multi_host:
        scope_score = 75.0
        scope_expl = "Activity observed across multiple distinct host systems."
    else:
        scope_score = 20.0
        scope_expl = "Activity is bounded to a single target host."

    components = [
        RiskScoreComponent(factor="Authentication Pattern", score=auth_score, weight=0.35, explanation=auth_expl),
        RiskScoreComponent(factor="Threat Intelligence", score=threat_score, weight=0.25, explanation=threat_expl),
        RiskScoreComponent(factor="Identity & Asset Impact", score=asset_score, weight=0.20, explanation=asset_expl),
        RiskScoreComponent(factor="Scope & Lateral Spread", score=scope_score, weight=0.20, explanation=scope_expl),
    ]

    overall = round(sum(c.score * c.weight for c in components), 1)
    explanation = f"Composite risk {overall}/100 based on weighted signals: auth={auth_score:.0f}, threat={threat_score:.0f}, asset={asset_score:.0f}, scope={scope_score:.0f}."
    return RiskScore(overall=overall, components=components, explanation=explanation)


def _timeline_and_correlate_pandas(events: list[NormalizedEvent], alert: AlertInput) -> tuple[list[Finding], list[TimelineEntry], bool, bool, bool]:
    """Correlate activities and reconstruct timeline using pandas with robust fallback."""
    refs = [f"{e.source_index}/{e.document_id} (event {e.event_id})" for e in events]
    if not events:
        empty_finding = Finding(
            title="No matching events retrieved",
            observed_facts=["The configured source returned no matching events."],
            inference="This may reflect incomplete coverage, filtering, or no activity.",
            evidence_refs=[f"alert:{alert.incident_id}"],
        )
        return [empty_finding], [], False, False, False

    findings: list[Finding] = []
    timeline: list[TimelineEntry] = []
    sequence = False
    spray_detected = False
    multi_host = False

    try:
        import pandas as pd

        records = [
            {
                "timestamp": e.timestamp,
                "event_id": e.event_id,
                "source_index": e.source_index,
                "document_id": e.document_id,
                "event_type": (e.event_type or "unknown").lower(),
                "outcome": (e.outcome or "").lower(),
                "username": e.username or "",
                "source_ip": e.source_ip or "",
                "hostname": e.hostname or "",
                "ref": f"{e.source_index}/{e.document_id} (event {e.event_id})",
                "original_event": e,
            }
            for e in events
        ]
        df = pd.DataFrame(records).sort_values("timestamp").reset_index(drop=True)

        # 1. Timeline reconstruction with pandas gap and collision analysis
        ts_counts = df["timestamp"].value_counts()
        time_diffs = df["timestamp"].diff().shift(-1)

        for idx, row in df.iterrows():
            parts = [row["event_type"]]
            if row["outcome"]:
                parts.append(row["outcome"])
            if row["username"]:
                parts.append(f"user={row['username']}")
            if row["source_ip"]:
                parts.append(f"ip={row['source_ip']}")
            if row["hostname"]:
                parts.append(f"host={row['hostname']}")

            uncertainty = None
            if ts_counts.get(row["timestamp"], 0) > 1:
                uncertainty = "Multiple events share this timestamp; their relative ordering is unknown."
            elif pd.notna(time_diffs[idx]) and time_diffs[idx] > pd.Timedelta(hours=1):
                uncertainty = "A gap longer than one hour follows; source coverage may be incomplete."

            timeline.append(TimelineEntry(
                timestamp=row["timestamp"],
                summary="; ".join(parts),
                evidence_refs=[row["ref"]],
                uncertainty=uncertainty,
            ))

        # 2. Correlation Rule 1: Brute-Force / Credential Guessing (Failures followed by Success for same user)
        auth_mask = df["event_type"].isin(["login", "authentication", "auth", "user_login"])
        auth_df = df[auth_mask]
        fails_df = auth_df[auth_df["outcome"].isin(["failure", "failed", "deny"])]
        success_df = auth_df[auth_df["outcome"].isin(["success", "succeeded", "allowed"])]

        for _, f in fails_df.iterrows():
            matches = success_df[
                (success_df["username"] == f["username"]) &
                (success_df["timestamp"] >= f["timestamp"]) &
                ((success_df["source_ip"] == "") | (f["source_ip"] == "") | (success_df["source_ip"] == f["source_ip"]))
            ]
            if not matches.empty:
                sequence = True
                break

        if sequence:
            auth_refs = list(auth_df["ref"])
            findings.append(Finding(
                title="Failed authentication followed by success",
                observed_facts=[f"Observed {len(fails_df)} failed and {len(success_df)} successful login events in the bounded window."],
                inference="The sequence may indicate password guessing or a user retry; it does not establish compromise.",
                evidence_refs=auth_refs if auth_refs else refs,
                mitre_mappings=[
                    MitreMapping(
                        technique_id="T1110.001",
                        technique_name="Brute Force: Password Guessing",
                        tactic="Credential Access",
                        reference_url="https://attack.mitre.org/techniques/T1110/001/",
                    ),
                    MitreMapping(
                        technique_id="T1078",
                        technique_name="Valid Accounts",
                        tactic="Defense Evasion, Persistence, Initial Access",
                        reference_url="https://attack.mitre.org/techniques/T1078/",
                    ),
                ],
            ))

        # 3. Correlation Rule 2: Credential Spray (Single IP targeting multiple distinct usernames)
        failed_by_ip = fails_df[fails_df["source_ip"] != ""].groupby("source_ip")["username"].nunique()
        spraying_ips = failed_by_ip[failed_by_ip >= 2].index.tolist()
        if spraying_ips:
            spray_detected = True
            spray_refs = list(fails_df[fails_df["source_ip"].isin(spraying_ips)]["ref"])
            findings.append(Finding(
                title="Potential credential spray activity",
                observed_facts=[f"Source IP(s) {', '.join(spraying_ips)} generated failed authentications across multiple distinct usernames."],
                inference="This pattern may represent distributed credential stuffing or horizontal enumeration.",
                evidence_refs=spray_refs,
                mitre_mappings=[
                    MitreMapping(
                        technique_id="T1110.003",
                        technique_name="Brute Force: Password Spraying",
                        tactic="Credential Access",
                        reference_url="https://attack.mitre.org/techniques/T1110/003/",
                    )
                ],
            ))

        # 4. Correlation Rule 3: Multi-Host Lateral Movement / Activity
        hosts_by_user = df[df["username"] != ""].groupby("username")["hostname"].nunique()
        multi_hosts = hosts_by_user[hosts_by_user >= 2].index.tolist()
        if multi_hosts and not sequence:
            multi_host = True
            mh_refs = list(df[df["username"].isin(multi_hosts)]["ref"])
            findings.append(Finding(
                title="Multi-host activity detected",
                observed_facts=[f"User(s) {', '.join(multi_hosts)} observed interacting with multiple distinct hostnames."],
                inference="Activity across distinct endpoints warrants confirmation of authorized operational workflow.",
                evidence_refs=mh_refs,
                mitre_mappings=[
                    MitreMapping(
                        technique_id="T1021",
                        technique_name="Remote Services",
                        tactic="Lateral Movement",
                        reference_url="https://attack.mitre.org/techniques/T1021/",
                    )
                ],
            ))

        if not findings:
            findings.append(Finding(
                title="Activity observed in the investigation window",
                observed_facts=[f"Retrieved {len(events)} unique events from the configured source."],
                evidence_refs=refs,
            ))

        return findings, timeline, sequence, spray_detected, multi_host

    except Exception:
        # Fallback to pure Python if pandas throws or is missing
        counts: dict[datetime, int] = {}
        for event in events:
            counts[event.timestamp] = counts.get(event.timestamp, 0) + 1
        for position, event in enumerate(events):
            parts = [event.event_type]
            if event.outcome:
                parts.append(event.outcome)
            if event.username:
                parts.append(f"user={event.username}")
            if event.source_ip:
                parts.append(f"ip={event.source_ip}")
            if event.hostname:
                parts.append(f"host={event.hostname}")
            ref = f"{event.source_index}/{event.document_id} (event {event.event_id})"
            uncertainty = "Multiple events share this timestamp; their relative ordering is unknown." if counts[event.timestamp] > 1 else None
            if position + 1 < len(events) and events[position + 1].timestamp - event.timestamp > timedelta(hours=1):
                uncertainty = "A gap longer than one hour follows; source coverage may be incomplete."
            timeline.append(TimelineEntry(timestamp=event.timestamp, summary="; ".join(parts), evidence_refs=[ref], uncertainty=uncertainty))

        auth_events = [e for e in events if e.event_type.lower() in {"login", "authentication", "auth", "user_login"}]
        fails = [e for e in auth_events if (e.outcome or "").lower() in {"failure", "failed", "deny"}]
        successes = [e for e in auth_events if (e.outcome or "").lower() in {"success", "succeeded", "allowed"}]
        sequence = any(f.username and s.username == f.username and f.timestamp <= s.timestamp and
                       (not f.source_ip or not s.source_ip or f.source_ip == s.source_ip)
                       for f in fails for s in successes)

        if sequence and refs:
            auth_refs = [f"{e.source_index}/{e.document_id} (event {e.event_id})" for e in auth_events]
            findings.append(Finding(
                title="Failed authentication followed by success",
                observed_facts=[f"Observed {len(fails)} failed and {len(successes)} successful login events in the bounded window."],
                inference="The sequence may indicate password guessing or a user retry; it does not establish compromise.",
                evidence_refs=auth_refs,
                mitre_mappings=[
                    MitreMapping(
                        technique_id="T1110.001",
                        technique_name="Brute Force: Password Guessing",
                        tactic="Credential Access",
                        reference_url="https://attack.mitre.org/techniques/T1110/001/",
                    )
                ],
            ))
        else:
            findings.append(Finding(
                title="Activity observed in the investigation window",
                observed_facts=[f"Retrieved {len(events)} unique events from the configured source."],
                evidence_refs=refs,
            ))

        return findings, timeline, sequence, False, False


class InvestigationService:
    def __init__(
        self,
        event_source: ReadOnlyEventSource | None = None,
        reputation: Any | None = None,
        geoip: GeoIPClient | None = None,
    ):
        if event_source is not None:
            self.event_source = event_source
        elif SETTINGS.mode.lower() == "elasticsearch":
            self.event_source = ElasticsearchReadOnlySource()
        else:
            self.event_source = SyntheticEventSource()
        if reputation is not None:
            self.reputation = reputation
        elif SETTINGS.abuseipdb_api_key:
            self.reputation = AbuseIPDBClient(SETTINGS.abuseipdb_api_key)
        else:
            # 100% Free, zero-API-key-required live public intelligence with seamless offline fallback
            self.reputation = FreeIPIntelClient()

        if geoip is not None:
            self.geoip = geoip
        elif hasattr(self.reputation, "lookup_geo"):
            self.geoip = self.reputation
        else:
            self.geoip = MockGeoIPClient()

    def plan_search_window(self, alert: AlertInput) -> SearchWindow:
        return SearchWindow(
            start=alert.timestamp - timedelta(hours=SETTINGS.lookback_hours),
            end=alert.timestamp + timedelta(hours=SETTINGS.lookahead_hours),
            max_results=SETTINGS.max_events,
            page_size=SETTINGS.page_size,
        )

    def retrieve_events(self, window: SearchWindow, indicator_values: list[str], audit: list[dict[str, Any]], warnings: list[str]) -> list[NormalizedEvent]:
        try:
            raw_events, source_warnings = self.event_source.search(window, indicator_values)
            warnings.extend(source_warnings)
            audit.append({
                "event": "read_only_search",
                "at": datetime.now(timezone.utc).isoformat(),
                "indices": list(SETTINGS.allowed_indices),
                "fields": list(ALLOWED_FIELDS),
                "window_start": window.start.isoformat(),
                "window_end": window.end.isoformat(),
                "max_results": window.max_results,
                "returned": len(raw_events),
            })
        except Exception as exc:
            raw_events = []
            warnings.append(f"Event search unavailable ({type(exc).__name__}).")
            audit.append({
                "event": "read_only_search_error",
                "at": datetime.now(timezone.utc).isoformat(),
                "error_type": type(exc).__name__,
            })

        deduped: dict[tuple[str, str], NormalizedEvent] = {}
        for event in raw_events:
            deduped[(event.source_index, event.document_id)] = event
        return sorted(deduped.values(), key=lambda e: e.timestamp)

    def enrich_indicators(self, events: list[NormalizedEvent], indicators: list[Indicator], audit: list[dict[str, Any]], warnings: list[str]) -> tuple[list[ThreatIntelResult], list[GeoLocation]]:
        ips = sorted({e.source_ip for e in events if _public_ip(e.source_ip)} | {i.value for i in indicators if i.kind == "ip" and _public_ip(i.value)})
        if len(ips) > 5:
            warnings.append(f"Reputation lookup limit reached (5 of {len(ips)} public IPs); remaining IPs were not queried.")
            ips = ips[:5]

        intel: list[ThreatIntelResult] = []
        geos: list[GeoLocation] = []

        for ip in ips:
            try:
                result = self.reputation.lookup(ip)
                intel.append(result)
            except Exception as exc:
                result = ThreatIntelResult(ip=ip, queried=False, lookup_time=datetime.now(timezone.utc), error=f"provider unavailable ({type(exc).__name__})")
                intel.append(result)
            audit.append({"event": "reputation_lookup", "at": datetime.now(timezone.utc).isoformat(), "ip": ip, "queried": result.queried})
            if result.error:
                warnings.append(f"Reputation enrichment unavailable for {ip}: {result.error}.")

            # Geolocation lookup (live free resource API with offline mock fallback)
            try:
                if hasattr(self.geoip, "lookup_geo"):
                    geos.append(self.geoip.lookup_geo(ip))
                else:
                    geos.append(self.geoip.lookup(ip))
            except Exception:
                pass

        return intel, geos

    def assess_risk_and_actions(self, alert: AlertInput, events: list[NormalizedEvent], sequence: bool, warnings: list[str]) -> tuple[Severity, str, list[RecommendedAction], str, list[str], list[str]]:
        severity = alert.severity
        rationale = "Initial alert severity retained because available evidence does not justify a change."
        if sequence and severity in {Severity.low, Severity.medium}:
            severity = Severity.high
            rationale = "Repeated failures followed by a success for the same user support elevated review; this is not proof of compromise."

        recommendations = [
            RecommendedAction(
                description="Review the cited authentication events and verify the successful login with the affected user through an established channel.",
                rationale="A same-user failure/success sequence warrants validation while preserving the distinction between observation and compromise.",
                urgency="high" if sequence else "medium",
                required_human_role="SOC analyst",
                validation_checks=[
                    "Confirm the user's expected activity and source location.",
                    "Check endpoint and identity provider telemetry for corroborating evidence.",
                ],
            )
        ]
        if sequence:
            recommendations.append(
                RecommendedAction(
                    description="If independent evidence confirms account compromise, follow the organization's approved identity containment procedure.",
                    rationale="Containment may be appropriate only after a security lead validates the evidence and impact.",
                    urgency="high",
                    required_human_role="Incident commander or identity administrator",
                    validation_checks=[
                        "Validate user identity and business impact.",
                        "Preserve relevant logs and document authorization before any change.",
                        "Confirm the approved recovery and rollback path.",
                    ],
                )
            )

        confidence_limits = []
        if not events:
            confidence_limits.append("No source events were available for corroboration.")
        if warnings:
            confidence_limits.append("One or more data dependencies returned partial results or errors.")
        confidence_limits.append("This demo uses deterministic rules and does not establish user intent, device ownership, or attribution.")

        unknowns = [
            "Whether the activity was expected by the affected user.",
            "Whether related endpoint or identity-provider events exist outside the configured sources.",
        ]
        confidence = "medium" if sequence and events and not warnings else "low"
        return severity, rationale, recommendations, confidence, confidence_limits, unknowns

    def investigate(self, alert: AlertInput) -> InvestigationReport:
        started = datetime.now(timezone.utc)
        audit: list[dict[str, Any]] = [{"event": "investigation_started", "at": started.isoformat(), "incident_id": alert.incident_id}]
        warnings: list[str] = []

        window = self.plan_search_window(alert)
        indicators = normalize_indicators(alert)
        events = self.retrieve_events(window, [i.value for i in indicators], audit, warnings)
        intel, geos = self.enrich_indicators(events, indicators, audit, warnings)

        findings, timeline, sequence, spray_detected, multi_host = _timeline_and_correlate_pandas(events, alert)
        severity, rationale, recommendations, confidence, confidence_limits, unknowns = self.assess_risk_and_actions(alert, events, sequence, warnings)

        risk_score = _calculate_risk_score(alert, events, sequence, intel, spray_detected, multi_host)

        status = InvestigationStatus.completed_with_warnings if warnings else InvestigationStatus.completed
        completed = datetime.now(timezone.utc)
        audit.append({"event": "report_generated", "at": completed.isoformat(), "event_count": len(events), "warning_count": len(warnings)})

        markdown = _markdown(alert, window, events, findings, severity, rationale, recommendations, warnings, risk_score)
        sources_queried = ["synthetic-events" if isinstance(self.event_source, SyntheticEventSource) else "elasticsearch-read-only"]
        if intel:
            if isinstance(self.reputation, MockReputationClient):
                sources_queried.append("offline-reputation-mock")
            elif isinstance(self.reputation, FreeIPIntelClient):
                sources_queried.append("ip-api.com (Free Public Resource API)")
            elif isinstance(self.reputation, AbuseIPDBClient):
                sources_queried.append("AbuseIPDB")
            else:
                sources_queried.append("configured-reputation-client")

        return InvestigationReport(
            incident_id=alert.incident_id,
            status=status,
            started_at=started,
            completed_at=completed,
            alert=alert,
            search_window=window,
            data_sources_queried=sources_queried,
            events=events,
            indicators=indicators,
            enrichment_results=intel,
            geo_locations=geos,
            timeline=timeline,
            findings=findings,
            risk_score=risk_score,
            recommended_severity=severity,
            severity_rationale=rationale,
            confidence=confidence,
            confidence_limits=confidence_limits,
            unknowns=unknowns,
            recommended_actions=recommendations,
            warnings=warnings,
            audit=audit,
            markdown_summary=markdown,
        )


def _markdown(alert, window, events, findings, severity, rationale, actions, warnings, risk_score: RiskScore | None = None) -> str:
    lines = [
        f"# Investigation {alert.incident_id}",
        "",
        "Human review support only; this is not a confirmed incident verdict.",
        "",
        f"- Status: completed{' with warnings' if warnings else ''}",
        f"- Search window (UTC): {window.start.isoformat()} to {window.end.isoformat()}",
        f"- Retrieved events: {len(events)}",
        f"- Recommended severity: **{severity.value}** — {rationale}",
    ]
    if risk_score:
        lines.append(f"- Composite Risk Score: **{risk_score.overall}/100** ({risk_score.explanation})")
    lines += ["", "## Findings"]
    for finding in findings:
        mitre_tag = ""
        if finding.mitre_mappings:
            mitre_tag = " [" + ", ".join([f"{m.technique_id} ({m.technique_name})" for m in finding.mitre_mappings]) + "]"
        lines.append(f"- **{finding.title}{mitre_tag}:** {' '.join(finding.observed_facts)} Evidence: {', '.join(finding.evidence_refs)}")
    lines += ["", "## Advisory-only next steps"]
    lines += [f"- {action.description} Rationale: {action.rationale}" for action in actions]
    if warnings:
        lines += ["", "## Warnings"] + [f"- {w}" for w in warnings]
    return "\n".join(lines)
