"""Explicit LangGraph orchestration with multi-node observable investigation stages."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, TypedDict

from .models import (
    AlertInput,
    Finding,
    GeoLocation,
    Indicator,
    InvestigationReport,
    InvestigationStatus,
    NormalizedEvent,
    RecommendedAction,
    RiskScore,
    SearchWindow,
    Severity,
    ThreatIntelResult,
    TimelineEntry,
    normalize_indicators,
)
from .pipeline import InvestigationService, _calculate_risk_score, _markdown
from .sources import AbuseIPDBClient, FreeIPIntelClient, MockReputationClient, SyntheticEventSource


class InvestigationState(TypedDict, total=False):
    alert: AlertInput
    indicators: list[Indicator]
    search_window: SearchWindow
    events: list[NormalizedEvent]
    enrichment_results: list[ThreatIntelResult]
    geo_locations: list[GeoLocation]
    findings: list[Finding]
    timeline: list[TimelineEntry]
    sequence_detected: bool
    spray_detected: bool
    multi_host_detected: bool
    risk_score: RiskScore
    recommended_severity: Severity
    severity_rationale: str
    confidence: str
    confidence_limits: list[str]
    unknowns: list[str]
    recommended_actions: list[RecommendedAction]
    warnings: list[str]
    audit: list[dict[str, Any]]
    started_at: datetime
    report: InvestigationReport
    error: str


def build_graph(service: InvestigationService | None = None):
    investigator = service or InvestigationService()

    def stage_validate_alert(state: InvestigationState) -> dict[str, Any]:
        try:
            alert = AlertInput.model_validate(state["alert"])
            started = datetime.now(timezone.utc)
            indicators = normalize_indicators(alert)
            audit = [{"event": "investigation_started", "at": started.isoformat(), "incident_id": alert.incident_id}]
            return {
                "alert": alert,
                "indicators": indicators,
                "started_at": started,
                "audit": audit,
                "warnings": list(state.get("warnings", [])),
            }
        except Exception as exc:
            return {"error": f"Invalid alert ({type(exc).__name__})."}

    def stage_plan_window(state: InvestigationState) -> dict[str, Any]:
        if state.get("error"):
            return {}
        window = investigator.plan_search_window(state["alert"])
        return {"search_window": window}

    def stage_retrieve_evidence(state: InvestigationState) -> dict[str, Any]:
        if state.get("error"):
            return {}
        audit = list(state.get("audit", []))
        warnings = list(state.get("warnings", []))
        indicator_values = [i.value for i in state.get("indicators", [])]
        events = investigator.retrieve_events(state["search_window"], indicator_values, audit, warnings)
        return {"events": events, "audit": audit, "warnings": warnings}

    def stage_enrich_indicators(state: InvestigationState) -> dict[str, Any]:
        if state.get("error"):
            return {}
        audit = list(state.get("audit", []))
        warnings = list(state.get("warnings", []))
        intel, geos = investigator.enrich_indicators(state.get("events", []), state.get("indicators", []), audit, warnings)
        return {"enrichment_results": intel, "geo_locations": geos, "audit": audit, "warnings": warnings}

    def stage_correlate_and_timeline(state: InvestigationState) -> dict[str, Any]:
        if state.get("error"):
            return {}
        from .pipeline import _timeline_and_correlate_pandas
        findings, timeline, sequence, spray, multi_host = _timeline_and_correlate_pandas(state.get("events", []), state["alert"])
        return {
            "findings": findings,
            "timeline": timeline,
            "sequence_detected": sequence,
            "spray_detected": spray,
            "multi_host_detected": multi_host,
        }

    def stage_assess_and_recommend(state: InvestigationState) -> dict[str, Any]:
        if state.get("error"):
            return {}
        warnings = list(state.get("warnings", []))
        sev, rationale, recs, conf, conf_limits, unknowns = investigator.assess_risk_and_actions(
            state["alert"], state.get("events", []), state.get("sequence_detected", False), warnings
        )
        risk = _calculate_risk_score(
            state["alert"],
            state.get("events", []),
            state.get("sequence_detected", False),
            state.get("enrichment_results", []),
            state.get("spray_detected", False),
            state.get("multi_host_detected", False),
        )
        return {
            "recommended_severity": sev,
            "severity_rationale": rationale,
            "recommended_actions": recs,
            "risk_score": risk,
            "confidence": conf,
            "confidence_limits": conf_limits,
            "unknowns": unknowns,
        }

    def stage_generate_brief(state: InvestigationState) -> dict[str, Any]:
        if state.get("error"):
            return {}
        alert = state["alert"]
        window = state["search_window"]
        events = state.get("events", [])
        findings = state.get("findings", [])
        severity = state["recommended_severity"]
        rationale = state["severity_rationale"]
        recs = state.get("recommended_actions", [])
        warnings = list(state.get("warnings", []))
        audit = list(state.get("audit", []))
        intel = state.get("enrichment_results", [])
        geos = state.get("geo_locations", [])
        indicators = state.get("indicators", [])
        timeline = state.get("timeline", [])
        risk = state.get("risk_score")
        started = state.get("started_at", datetime.now(timezone.utc))
        completed = datetime.now(timezone.utc)

        status = InvestigationStatus.completed_with_warnings if warnings else InvestigationStatus.completed
        audit.append({"event": "report_generated", "at": completed.isoformat(), "event_count": len(events), "warning_count": len(warnings)})
        markdown = _markdown(alert, window, events, findings, severity, rationale, recs, warnings, risk)

        sources_queried = ["synthetic-events" if isinstance(investigator.event_source, SyntheticEventSource) else "elasticsearch-read-only"]
        if intel:
            if isinstance(investigator.reputation, MockReputationClient):
                sources_queried.append("offline-reputation-mock")
            elif isinstance(investigator.reputation, FreeIPIntelClient):
                sources_queried.append("ip-api.com (Free Public Resource API)")
            elif isinstance(investigator.reputation, AbuseIPDBClient):
                sources_queried.append("AbuseIPDB")
            else:
                sources_queried.append("configured-reputation-client")

        report = InvestigationReport(
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
            risk_score=risk,
            recommended_severity=severity,
            severity_rationale=rationale,
            confidence=state.get("confidence", "low"),
            confidence_limits=state.get("confidence_limits", []),
            unknowns=state.get("unknowns", []),
            recommended_actions=recs,
            warnings=warnings,
            audit=audit,
            markdown_summary=markdown,
        )
        return {"report": report}

    try:
        from langgraph.graph import END, START, StateGraph

        graph = StateGraph(InvestigationState)
        graph.add_node("validate_alert", stage_validate_alert)
        graph.add_node("plan_search_window", stage_plan_window)
        graph.add_node("retrieve_evidence", stage_retrieve_evidence)
        graph.add_node("enrich_indicators", stage_enrich_indicators)
        graph.add_node("correlate_and_timeline", stage_correlate_and_timeline)
        graph.add_node("assess_and_recommend", stage_assess_and_recommend)
        graph.add_node("generate_brief", stage_generate_brief)

        graph.add_edge(START, "validate_alert")
        graph.add_edge("validate_alert", "plan_search_window")
        graph.add_edge("plan_search_window", "retrieve_evidence")
        graph.add_edge("retrieve_evidence", "enrich_indicators")
        graph.add_edge("enrich_indicators", "correlate_and_timeline")
        graph.add_edge("correlate_and_timeline", "assess_and_recommend")
        graph.add_edge("assess_and_recommend", "generate_brief")
        graph.add_edge("generate_brief", END)
        return graph.compile()

    except ImportError:
        class SequentialMultiStageFallback:
            def invoke(self, state: InvestigationState) -> dict[str, Any]:
                cur: dict[str, Any] = dict(state)
                for step_fn in (
                    stage_validate_alert,
                    stage_plan_window,
                    stage_retrieve_evidence,
                    stage_enrich_indicators,
                    stage_correlate_and_timeline,
                    stage_assess_and_recommend,
                    stage_generate_brief,
                ):
                    out = step_fn(cur)
                    cur.update(out)
                    if cur.get("error"):
                        return cur

                report: InvestigationReport = cur["report"]
                warning = "LangGraph runtime unavailable; deterministic sequential workflow used."
                if warning not in report.warnings:
                    report.warnings.append(warning)
                report.status = InvestigationStatus.completed_with_warnings
                report.audit.append({"event": "workflow_fallback", "reason": "langgraph_import_failed"})
                if "## Warnings" in report.markdown_summary:
                    if warning not in report.markdown_summary:
                        report.markdown_summary += f"\n- {warning}"
                else:
                    report.markdown_summary += f"\n\n## Warnings\n- {warning}"
                return cur

        return SequentialMultiStageFallback()
