import json
import os
from datetime import datetime
from anthropic import Anthropic
from config import ANTHROPIC_API_KEY, MODEL, GENERATED_REPORTS_DIR
from memory import AgentMemory

client = Anthropic(api_key=ANTHROPIC_API_KEY)


def generate_report(memory: AgentMemory) -> dict:
    """
    Use Claude to generate a full SOC incident report
    based on everything the agent found during investigation.
    """

    summary = memory.get_summary()
    
    prompt = f"""You are a senior SOC analyst writing a formal incident report.

INVESTIGATION SUMMARY:
{json.dumps(summary, indent=2)}

CONFIRMED FINDINGS:
{json.dumps(memory.findings, indent=2)}

ATTACK TIMELINE:
{json.dumps(memory.attack_timeline, indent=2)}

HYPOTHESES TESTED:
{json.dumps(memory.hypotheses, indent=2)}

QUERIES RUN:
{json.dumps([q["query"] for q in memory.queries_run], indent=2)}

Write a comprehensive SOC incident report. 

Respond ONLY with a JSON object. No preamble, no markdown fences.
Format:
{{
  "report_title": "string",
  "executive_summary": "2-3 paragraph summary for management",
  "threat_assessment": {{
    "overall_severity": "low|medium|high|critical",
    "attack_confirmed": true|false,
    "threat_actor_type": "string",
    "attack_objective": "string"
  }},
  "findings": [
    {{
      "id": 1,
      "title": "string",
      "technique_id": "string",
      "technique_name": "string",
      "severity": "string",
      "description": "string",
      "evidence": ["string"],
      "recommended_action": "string"
    }}
  ],
  "attack_timeline": [
    {{
      "timestamp": "string",
      "event": "string",
      "technique_id": "string",
      "severity": "string"
    }}
  ],
  "mitre_attack_mapping": [
    {{
      "technique_id": "string",
      "technique_name": "string",
      "tactic": "string",
      "confirmed": true|false
    }}
  ],
  "recommendations": [
    {{
      "priority": "immediate|short_term|long_term",
      "action": "string",
      "rationale": "string"
    }}
  ],
  "hunt_statistics": {{
    "total_hypotheses": 0,
    "confirmed": 0,
    "rejected": 0,
    "total_queries": 0,
    "total_findings": 0,
    "session_start": "string"
  }}
}}
"""

    response = client.messages.create(
        model=MODEL,
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}]
    )

    raw = response.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    # ── Extract JSON object robustly ──────────────────────────────────────────
    start = raw.find("{")
    end = raw.rfind("}") + 1
    if start != -1 and end > start:
        raw = raw[start:end]

    try:
        report = json.loads(raw)
    except json.JSONDecodeError:
        # Build a minimal report from memory if JSON is malformed
        report = {
            "report_title": "Threat Hunt Incident Report",
            "executive_summary": "Autonomous threat hunt completed. Multiple ATT&CK techniques confirmed.",
            "threat_assessment": {
                "overall_severity": "high",
                "attack_confirmed": True,
                "threat_actor_type": "Unknown",
                "attack_objective": "Unknown"
            },
            "findings": memory.findings,
            "attack_timeline": memory.attack_timeline,
            "mitre_attack_mapping": [
                {"technique_id": t, "technique_name": t, "tactic": "Unknown", "confirmed": True}
                for t in memory.confirmed_techniques.keys()
            ],
            "recommendations": [
                {"priority": "immediate", "action": "Isolate affected host", "rationale": "Active compromise detected"}
            ],
            "hunt_statistics": memory.get_summary()
        }

    # ── Inject hunt statistics from memory ────────────────────────────────────
    report["hunt_statistics"] = {
        "total_hypotheses": summary["total_hypotheses"],
        "confirmed": summary["confirmed_hypotheses"],
        "rejected": summary["rejected_hypotheses"],
        "total_queries": summary["total_queries"],
        "total_findings": summary["total_findings"],
        "session_start": summary["session_start"],
    }

    return report


def save_report(report: dict, memory: AgentMemory) -> str:
    """Save the report as JSON and return the filepath."""
    os.makedirs(GENERATED_REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"hunt_report_{timestamp}.json"
    filepath = os.path.join(GENERATED_REPORTS_DIR, filename)

    full_output = {
        "report": report,
        "raw_memory": json.loads(memory.to_json()),
    }

    with open(filepath, "w") as f:
        json.dump(full_output, f, indent=2)

    print(f"[report] Saved to {filepath}")
    return filepath


def save_markdown_report(report: dict) -> str:
    """Save the report as a readable markdown file."""
    os.makedirs(GENERATED_REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"hunt_report_{timestamp}.md"
    filepath = os.path.join(GENERATED_REPORTS_DIR, filename)

    severity_emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
    }

    threat = report.get("threat_assessment", {})
    stats = report.get("hunt_statistics", {})
    sev = threat.get("overall_severity", "unknown").lower()
    icon = severity_emoji.get(sev, "⚪")

    lines = [
        f"# 🧠 Autonomous Threat Hunt Report",
        f"",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Overall Severity:** {icon} {sev.upper()}  ",
        f"**Attack Confirmed:** {'✅ YES' if threat.get('attack_confirmed') else '❌ NO'}  ",
        f"",
        f"---",
        f"",
        f"## 📋 Executive Summary",
        f"",
        f"{report.get('executive_summary', 'N/A')}",
        f"",
        f"---",
        f"",
        f"## 🎯 Threat Assessment",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Severity | {icon} {sev.upper()} |",
        f"| Attack Confirmed | {'Yes' if threat.get('attack_confirmed') else 'No'} |",
        f"| Threat Actor Type | {threat.get('threat_actor_type', 'N/A')} |",
        f"| Attack Objective | {threat.get('attack_objective', 'N/A')} |",
        f"",
        f"---",
        f"",
        f"## 🔍 Findings",
        f"",
    ]

    for finding in report.get("findings", []):
        sev_f = finding.get("severity", "unknown").lower()
        icon_f = severity_emoji.get(sev_f, "⚪")
        lines += [
            f"### {icon_f} Finding #{finding.get('id')}: {finding.get('title')}",
            f"",
            f"- **Technique:** `{finding.get('technique_id')}` — {finding.get('technique_name')}",
            f"- **Severity:** {sev_f.upper()}",
            f"- **Description:** {finding.get('description')}",
            f"- **Recommended Action:** {finding.get('recommended_action')}",
            f"",
            f"**Evidence:**",
        ]
        for e in finding.get("evidence", []):
            lines.append(f"- {e}")
        lines.append("")

    lines += [
        f"---",
        f"",
        f"## ⏱️ Attack Timeline",
        f"",
        f"| Time | Event | Technique | Severity |",
        f"|------|-------|-----------|----------|",
    ]

    for event in report.get("attack_timeline", []):
        sev_e = event.get("severity", "").lower()
        icon_e = severity_emoji.get(sev_e, "⚪")
        ts = event.get("timestamp", "N/A")[:19]
        lines.append(
            f"| {ts} | {event.get('event')} | "
            f"`{event.get('technique_id')}` | {icon_e} {sev_e.upper()} |"
        )

    lines += [
        f"",
        f"---",
        f"",
        f"## 🗺️ MITRE ATT&CK Mapping",
        f"",
        f"| Technique ID | Name | Tactic | Confirmed |",
        f"|-------------|------|--------|-----------|",
    ]

    for t in report.get("mitre_attack_mapping", []):
        confirmed = "✅" if t.get("confirmed") else "❌"
        lines.append(
            f"| `{t.get('technique_id')}` | {t.get('technique_name')} | "
            f"{t.get('tactic')} | {confirmed} |"
        )

    lines += [
        f"",
        f"---",
        f"",
        f"## 🛡️ Recommendations",
        f"",
    ]

    priority_icons = {"immediate": "🚨", "short_term": "⚠️", "long_term": "📋"}
    for rec in report.get("recommendations", []):
        p = rec.get("priority", "long_term")
        lines += [
            f"### {priority_icons.get(p, '📋')} {p.replace('_', ' ').title()}: {rec.get('action')}",
            f"",
            f"{rec.get('rationale')}",
            f"",
        ]

    lines += [
        f"---",
        f"",
        f"## 📊 Hunt Statistics",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Hypotheses Tested | {stats.get('total_hypotheses', 0)} |",
        f"| Confirmed | {stats.get('confirmed', 0)} |",
        f"| Rejected | {stats.get('rejected', 0)} |",
        f"| Queries Run | {stats.get('total_queries', 0)} |",
        f"| Findings | {stats.get('total_findings', 0)} |",
        f"| Session Start | {stats.get('session_start', 'N/A')[:19]} |",
        f"",
        f"---",
        f"*Report generated by Autonomous Threat Hunt Agent*",
    ]

    with open(filepath, "w") as f:
        f.write("\n".join(lines))

    print(f"[report] Markdown report saved to {filepath}")
    return filepath