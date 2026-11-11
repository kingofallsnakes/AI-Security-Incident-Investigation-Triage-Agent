from __future__ import annotations

import json
from typing import Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import ValidationError

from .graph import build_graph
from .models import AlertInput, InvestigationReport

app = FastAPI(
    title="AI Security Incident Investigation & Triage Agent",
    version="0.3.0",
    description="Human-supervised, read-only security incident investigation and triage demo",
)
_graph = build_graph()
_reports: dict[str, InvestigationReport] = {}

SAMPLE_ALERT_PAYLOAD = {
    "incident_id": "INC-DEMO-1001",
    "source": "identity-monitor",
    "severity": "medium",
    "timestamp": "2026-11-10T13:50:00-05:00",
    "affected_user": "analyst-demo",
    "affected_host": "workstation-7",
    "indicators": [
        {"kind": "ip", "value": "198.51.100.23", "source": "alert-rule", "context": "synthetic source address"},
        {"kind": "ip", "value": "8.8.8.8", "source": "alert-rule", "context": "synthetic related entity"},
    ],
    "description": "Multiple failed logins followed by successful authentication on workstation-7.",
}


@app.get("/", response_class=HTMLResponse)
def root(request: Request, format: str | None = None):
    accept = request.headers.get("accept", "")
    if format == "json" or ("application/json" in accept and "text/html" not in accept):
        return JSONResponse({
            "service": "AI Security Incident Investigation & Triage Agent",
            "version": "0.3.0",
            "status": "online",
            "docs_url": "/docs",
            "dashboard_url": "/dashboard",
            "endpoints": {
                "create_investigation": "POST /investigations",
                "get_investigation": "GET /investigations/{incident_id}",
            },
        })
    return HTMLResponse(content=_dashboard_html())


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(content=_dashboard_html())


@app.post("/investigations", response_model=InvestigationReport)
def create_investigation(payload: AlertInput):
    result = _graph.invoke({"alert": payload})
    if result.get("error"):
        raise HTTPException(status_code=422, detail=result["error"])
    report = result["report"]
    _reports[report.incident_id] = report
    return report


@app.get("/investigations/{incident_id}", response_model=InvestigationReport)
def get_investigation(incident_id: str):
    report = _reports.get(incident_id)
    if not report:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return report


def _dashboard_html() -> str:
    sample_json = json.dumps(SAMPLE_ALERT_PAYLOAD, indent=2)
    return f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SOC Triage & Incident Investigation Agent</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body {{ background-color: #0b1120; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
    ::-webkit-scrollbar-track {{ background: #0b1120; }}
    ::-webkit-scrollbar-thumb {{ background: #334155; border-radius: 3px; }}
  </style>
</head>
<body class="min-h-screen flex flex-col">
  <!-- Top Navigation -->
  <header class="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-50 px-6 py-3 flex items-center justify-between">
    <div class="flex items-center space-x-3">
      <div class="w-8 h-8 rounded-lg bg-sky-500/20 text-sky-400 border border-sky-500/40 flex items-center justify-center font-bold text-lg">🛡️</div>
      <div>
        <h1 class="text-base font-semibold text-white tracking-wide">SOC Incident Triage & Investigation Agent</h1>
        <p class="text-xs text-slate-400">Human-Supervised &bull; Read-Only Boundaries &bull; Evidence-Backed Briefs &bull; MITRE ATT&CK</p>
      </div>
    </div>
    <div class="flex items-center space-x-3">
      <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-950 text-emerald-400 border border-emerald-800">
        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5 animate-pulse"></span> Read-Only Active
      </span>
      <a href="/docs" target="_blank" class="text-xs text-sky-400 hover:text-sky-300 transition border border-sky-500/30 px-3 py-1.5 rounded-md hover:bg-sky-500/10">
        Swagger API Docs &rarr;
      </a>
    </div>
  </header>

  <!-- Main Container -->
  <main class="flex-1 max-w-7xl w-full mx-auto p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
    <!-- Left Column: Alert Ingestion / Controller -->
    <div class="lg:col-span-5 flex flex-col space-y-4">
      <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl">
        <div class="flex items-center justify-between mb-3">
          <h2 class="text-sm font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <span>📥</span> Alert Intake Sandbox
          </h2>
          <button onclick="loadSampleAlert()" class="text-xs text-sky-400 hover:underline">Reset Sample</button>
        </div>
        <p class="text-xs text-slate-400 mb-3">
          Paste an anomalous alert payload. The agent will normalize indicators, plan bounded log searches, query threat intel, correlate activity, map MITRE ATT&CK techniques, and compute a composite risk score.
        </p>

        <textarea id="alertPayload" rows="13" class="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs mono text-slate-200 focus:outline-none focus:border-sky-500 transition resize-y">{sample_json}</textarea>

        <div class="mt-4 flex items-center gap-3">
          <button id="runBtn" onclick="runInvestigation()" class="flex-1 bg-sky-600 hover:bg-sky-500 text-white font-medium py-2.5 px-4 rounded-lg text-xs transition flex items-center justify-center gap-2 shadow-lg shadow-sky-900/30">
            <span>⚡</span> Run Investigation
          </button>
        </div>
      </div>

      <!-- Security Guardrails Card -->
      <div class="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4 text-xs text-slate-400 space-y-2">
        <div class="font-semibold text-slate-300 flex items-center gap-1.5">
          <span>🔒</span> Enforced Security Invariants
        </div>
        <ul class="list-disc pl-4 space-y-1 text-slate-400">
          <li><strong>Read-only execution:</strong> No host isolation or firewall changes possible.</li>
          <li><strong>Prompt injection defense:</strong> Log text is treated as inert data, never instructions.</li>
          <li><strong>Secret scrubbing:</strong> Passwords, session cookies, and tokens automatically redacted.</li>
          <li><strong>RFC IP filtering:</strong> Private/reserved ranges are never sent to external intelligence.</li>
          <li><strong>Human sign-off:</strong> Containment procedures are advisory only with checklist validation.</li>
        </ul>
      </div>
    </div>

    <!-- Right Column: Investigation Brief & Timeline -->
    <div class="lg:col-span-7 flex flex-col space-y-4">
      <!-- Status & Severity Banner -->
      <div id="statusBanner" class="hidden bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl">
        <div class="flex items-start justify-between flex-wrap gap-3">
          <div>
            <div class="flex items-center gap-2 mb-1">
              <span id="incidentBadge" class="text-xs mono font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300">INC-DEMO-1001</span>
              <span id="statusTag" class="text-xs px-2 py-0.5 rounded-full font-medium bg-emerald-950 text-emerald-400 border border-emerald-800">Completed</span>
            </div>
            <div class="text-sm font-semibold text-white flex items-center gap-2 mt-2">
              <span>Recommended Severity:</span>
              <span id="severityTag" class="px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-wider bg-rose-900/80 text-rose-200 border border-rose-700">HIGH</span>
            </div>
            <p id="severityRationale" class="text-xs text-slate-300 mt-1 italic"></p>
          </div>
          <div class="flex items-center gap-2">
            <button onclick="copyMarkdown()" class="text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3 py-1.5 rounded-md transition flex items-center gap-1.5">
              <span>📋</span> Copy Brief
            </button>
            <button onclick="downloadJson()" class="text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3 py-1.5 rounded-md transition flex items-center gap-1.5">
              <span>💾</span> JSON
            </button>
          </div>
        </div>

        <!-- Meta Metrics -->
        <div class="grid grid-cols-3 gap-2 mt-4 pt-4 border-t border-slate-800 text-xs">
          <div>
            <span class="text-slate-500 block">Search Window</span>
            <span id="windowMeta" class="mono text-slate-300 text-[11px]">-</span>
          </div>
          <div>
            <span class="text-slate-500 block">Retrieved Events</span>
            <span id="eventCountMeta" class="mono text-slate-300 font-bold">0</span>
          </div>
          <div>
            <span class="text-slate-500 block">Confidence Level</span>
            <span id="confidenceMeta" class="mono text-slate-300 font-semibold uppercase">MEDIUM</span>
          </div>
        </div>
      </div>

      <!-- Risk Score Card -->
      <div id="riskScoreCard" class="hidden bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <span>📊</span> Composite SOC Risk Score
          </h3>
          <span id="riskScoreTotal" class="text-sm font-bold mono px-2.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
            0 / 100
          </span>
        </div>
        <p id="riskScoreExpl" class="text-xs text-slate-400 mb-3"></p>
        <div id="riskScoreComponents" class="grid grid-cols-2 gap-2 text-xs"></div>
      </div>

      <!-- Placeholder Before Investigation -->
      <div id="emptyState" class="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center flex flex-col items-center justify-center flex-1">
        <div class="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center text-2xl mb-3">🔍</div>
        <h3 class="text-sm font-medium text-slate-200">No Investigation Active</h3>
        <p class="text-xs text-slate-500 max-w-sm mt-1">
          Click "Run Investigation" on the left to trigger bounded log searches, correlation, and advisory brief compilation.
        </p>
      </div>

      <!-- Investigation Content Accordion -->
      <div id="briefContent" class="hidden space-y-4">
        <!-- Findings Card -->
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl">
          <h3 class="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
            <span>🔎</span> Observed Findings & Inferences (MITRE ATT&CK Mapped)
          </h3>
          <div id="findingsList" class="space-y-3"></div>
        </div>

        <!-- Reconstructed Timeline -->
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl">
          <h3 class="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
            <span>⏱️</span> Reconstructed Timeline
          </h3>
          <div id="timelineContainer" class="space-y-2 border-l border-slate-800 ml-2 pl-4"></div>
        </div>

        <!-- Advisory Next Steps -->
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl">
          <div class="flex items-center justify-between mb-2">
            <h3 class="text-xs font-semibold text-amber-400 uppercase tracking-wider flex items-center gap-2">
              <span>🛡️</span> Advisory-Only Response Procedures
            </h3>
            <span class="text-[10px] uppercase font-bold bg-amber-950 text-amber-300 border border-amber-800 px-2 py-0.5 rounded">Human Sign-off Mandatory</span>
          </div>
          <p class="text-xs text-slate-400 mb-3">The system never modifies infrastructure directly. Recommended steps for the SOC team:</p>
          <div id="actionsList" class="space-y-3"></div>
        </div>

        <!-- Threat Intel & GeoIP Card -->
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl">
          <h3 class="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
            <span>🌐</span> Threat Intelligence & Geolocation Attribution
          </h3>
          <div id="intelList" class="space-y-2"></div>
        </div>
      </div>
    </div>
  </main>

  <script>
    const samplePayload = {sample_json};
    let currentReport = null;

    function loadSampleAlert() {{
      document.getElementById("alertPayload").value = JSON.stringify(samplePayload, null, 2);
    }}

    async function runInvestigation() {{
      const btn = document.getElementById("runBtn");
      const textarea = document.getElementById("alertPayload");
      let payload;
      try {{
        payload = JSON.parse(textarea.value);
      }} catch (e) {{
        alert("Invalid JSON: " + e.message);
        return;
      }}

      btn.disabled = true;
      btn.innerHTML = `<span class="animate-spin inline-block mr-2">🔄</span> Investigating...`;

      try {{
        const response = await fetch("/investigations", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify(payload)
        }});

        if (!response.ok) {{
          const err = await response.json();
          throw new Error(err.detail || JSON.stringify(err));
        }}

        currentReport = await response.json();
        renderReport(currentReport);
      }} catch (err) {{
        alert("Investigation Failed: " + err.message);
      }} finally {{
        btn.disabled = false;
        btn.innerHTML = `<span>⚡</span> Run Investigation`;
      }}
    }}

    function renderReport(r) {{
      document.getElementById("emptyState").classList.add("hidden");
      document.getElementById("statusBanner").classList.remove("hidden");
      document.getElementById("riskScoreCard").classList.remove("hidden");
      document.getElementById("briefContent").classList.remove("hidden");

      document.getElementById("incidentBadge").innerText = r.incident_id;
      document.getElementById("statusTag").innerText = r.status.replace("_", " ").toUpperCase();
      document.getElementById("severityTag").innerText = r.recommended_severity.toUpperCase();
      document.getElementById("severityRationale").innerText = r.severity_rationale;

      // Color code severity
      const sevTag = document.getElementById("severityTag");
      sevTag.className = "px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-wider ";
      if (r.recommended_severity === "critical" || r.recommended_severity === "high") {{
        sevTag.className += "bg-rose-950 text-rose-300 border border-rose-800";
      }} else if (r.recommended_severity === "medium") {{
        sevTag.className += "bg-amber-950 text-amber-300 border border-amber-800";
      }} else {{
        sevTag.className += "bg-emerald-950 text-emerald-300 border border-emerald-800";
      }}

      // Meta
      document.getElementById("windowMeta").innerText = `${{r.search_window.start.slice(0, 16)}} → ${{r.search_window.end.slice(0, 16)}}`;
      document.getElementById("eventCountMeta").innerText = r.events.length;
      document.getElementById("confidenceMeta").innerText = r.confidence;

      // Risk score
      if (r.risk_score) {{
        const rsTotal = document.getElementById("riskScoreTotal");
        rsTotal.innerText = `${{r.risk_score.overall}} / 100`;
        if (r.risk_score.overall >= 70) {{
          rsTotal.className = "text-sm font-bold mono px-2.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800";
        }} else if (r.risk_score.overall >= 40) {{
          rsTotal.className = "text-sm font-bold mono px-2.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800";
        }} else {{
          rsTotal.className = "text-sm font-bold mono px-2.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800";
        }}
        document.getElementById("riskScoreExpl").innerText = r.risk_score.explanation;
        const compContainer = document.getElementById("riskScoreComponents");
        compContainer.innerHTML = r.risk_score.components.map(c => `
          <div class="bg-slate-950 border border-slate-800 rounded p-2 text-[11px]">
            <div class="flex justify-between font-medium text-slate-300 mb-1">
              <span>${{c.factor}}</span>
              <span class="mono font-bold">${{c.score.toFixed(0)}} (${{Math.round(c.weight * 100)}}%)</span>
            </div>
            <div class="w-full bg-slate-800 rounded-full h-1.5 mb-1">
              <div class="bg-sky-500 h-1.5 rounded-full" style="width: ${{c.score}}%"></div>
            </div>
            <div class="text-[10px] text-slate-500">${{c.explanation}}</div>
          </div>
        `).join("");
      }}

      // Findings with MITRE badges
      const fContainer = document.getElementById("findingsList");
      fContainer.innerHTML = r.findings.map(f => `
        <div class="bg-slate-950 border border-slate-800/80 rounded-lg p-3 text-xs">
          <div class="font-semibold text-slate-200 mb-1 flex items-center justify-between flex-wrap gap-2">
            <span>${{f.title}}</span>
            ${{f.mitre_mappings && f.mitre_mappings.length ? `
              <div class="flex gap-1.5 flex-wrap">
                ${{f.mitre_mappings.map(m => `
                  <a href="${{m.reference_url}}" target="_blank" class="px-2 py-0.5 rounded text-[10px] mono bg-sky-950 text-sky-300 border border-sky-800 hover:bg-sky-900 transition">
                    MITRE ${{m.technique_id}}: ${{m.technique_name}}
                  </a>
                `).join("")}}
              </div>
            ` : ""}}
          </div>
          <ul class="list-disc pl-4 text-slate-300 space-y-0.5 mb-2">
            ${{f.observed_facts.map(fact => `<li>${{fact}}</li>`).join("")}}
          </ul>
          ${{f.inference ? `<div class="bg-sky-950/40 border border-sky-900/40 rounded p-2 text-sky-300 text-[11px] mb-2"><strong>Inference:</strong> ${{f.inference}}</div>` : ""}}
          <div class="text-[11px] text-slate-500 mono">
            <strong>Evidence Refs:</strong> ${{f.evidence_refs.join(", ")}}
          </div>
        </div>
      `).join("");

      // Timeline
      const tContainer = document.getElementById("timelineContainer");
      tContainer.innerHTML = r.timeline.map(t => `
        <div class="relative mb-3 group">
          <div class="absolute -left-[21px] top-1.5 w-2.5 h-2.5 rounded-full bg-sky-500 ring-4 ring-slate-900"></div>
          <div class="bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs">
            <div class="flex items-center justify-between text-[11px] text-slate-400 mono mb-1">
              <span>${{t.timestamp.replace("T", " ").replace("Z", " UTC")}}</span>
              <span class="text-slate-500">${{t.evidence_refs[0] || ""}}</span>
            </div>
            <div class="text-slate-200 mono text-xs">${{t.summary}}</div>
            ${{t.uncertainty ? `<div class="mt-1 text-[10px] text-amber-400/90 italic">⚠️ ${{t.uncertainty}}</div>` : ""}}
          </div>
        </div>
      `).join("");

      // Advisory Actions
      const aContainer = document.getElementById("actionsList");
      aContainer.innerHTML = r.recommended_actions.map(a => `
        <div class="bg-slate-950 border border-slate-800/80 rounded-lg p-3 text-xs">
          <div class="flex items-center justify-between mb-1.5">
            <span class="font-semibold text-slate-200">${{a.description}}</span>
            <span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold ${{a.urgency === 'high' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-slate-800 text-slate-300'}}">${{a.urgency}} urgency</span>
          </div>
          <p class="text-slate-400 text-xs mb-2 italic">Rationale: ${{a.rationale}}</p>
          <div class="text-[11px] text-slate-400 mb-2">
            <strong>Required Role:</strong> <span class="text-sky-300">${{a.required_human_role}}</span>
          </div>
          ${{a.validation_checks && a.validation_checks.length ? `
            <div class="bg-slate-900/80 rounded p-2 mt-2">
              <span class="text-[10px] uppercase text-slate-500 font-bold block mb-1">Prerequisite Validation Checks:</span>
              <div class="space-y-1">
                ${{a.validation_checks.map(chk => `
                  <label class="flex items-center gap-2 text-slate-300 text-[11px]">
                    <input type="checkbox" class="rounded bg-slate-800 border-slate-700 text-sky-500">
                    <span>${{chk}}</span>
                  </label>
                `).join("")}}
              </div>
            </div>
          ` : ""}}
        </div>
      `).join("");

      // Threat Intel & Geo
      const iContainer = document.getElementById("intelList");
      if (!r.enrichment_results || r.enrichment_results.length === 0) {{
        iContainer.innerHTML = `<div class="text-xs text-slate-500 italic">No public IPs required external enrichment.</div>`;
      }} else {{
        const geoMap = {{}};
        if (r.geo_locations) {{
          r.geo_locations.forEach(g => {{ geoMap[g.ip] = g; }});
        }}
        iContainer.innerHTML = r.enrichment_results.map(intel => {{
          const geo = geoMap[intel.ip];
          const geoText = geo && geo.country_name ? `${{geo.country_name}} (${{geo.city || 'Unknown City'}})` : "Location unmapped";
          return `
            <div class="bg-slate-950 border border-slate-800 rounded p-2.5 text-xs flex items-center justify-between">
              <div>
                <span class="mono font-semibold text-slate-200">${{intel.ip}}</span>
                <span class="text-slate-500 text-[11px] ml-2">📍 ${{geoText}}</span>
                <span class="text-slate-500 text-[11px] ml-2">&bull; ${{intel.provider}}</span>
                ${{intel.error ? `<span class="text-amber-400 text-[11px] ml-2">${{intel.error}}</span>` : ""}}
              </div>
              <div>
                <span class="px-2 py-0.5 rounded text-[11px] mono ${{intel.abuse_confidence_score > 50 ? 'bg-rose-950 text-rose-300' : 'bg-slate-800 text-slate-300'}}">
                  Abuse: ${{intel.abuse_confidence_score ?? 'N/A'}}%
                </span>
              </div>
            </div>
          `;
        }}).join("");
      }}
    }}

    function copyMarkdown() {{
      if (!currentReport || !currentReport.markdown_summary) return;
      navigator.clipboard.writeText(currentReport.markdown_summary).then(() => {{
        alert("Markdown Brief copied to clipboard!");
      }});
    }}

    function downloadJson() {{
      if (!currentReport) return;
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentReport, null, 2));
      const a = document.createElement('a');
      a.setAttribute("href", dataStr);
      a.setAttribute("download", `${{currentReport.incident_id}}_report.json`);
      document.body.appendChild(a);
      a.click();
      a.remove();
    }}
  </script>
</body>
</html>"""
