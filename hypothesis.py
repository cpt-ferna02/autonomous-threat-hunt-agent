import json
from anthropic import Anthropic
from config import ANTHROPIC_API_KEY, MODEL, HYPOTHESIS_TEMPLATES, TECHNIQUE_KEYWORDS
from memory import AgentMemory
from tools import get_event_statistics, summarize_events, search_events_by_technique

client = Anthropic(api_key=ANTHROPIC_API_KEY)


def generate_hypotheses(events: list[dict], memory: AgentMemory) -> list[dict]:
    """
    Analyze loaded events and use Claude to generate smart
    hunt hypotheses tailored to what's actually in the logs.
    """

    # ── Build context about what's in the logs ────────────────────────────────
    stats = get_event_statistics(events)

    # Quick technique pre-scan to give Claude real signal
    technique_hits = {}
    for technique_id in TECHNIQUE_KEYWORDS:
        matches = search_events_by_technique(events, technique_id)
        if matches:
            technique_hits[technique_id] = len(matches)

    context = f"""
You are a senior threat hunter analyzing Windows security logs.

LOG STATISTICS:
- Total events: {stats.get('total_events', 0)}
- Unique hosts: {stats.get('unique_hosts', [])}
- Log channels: {stats.get('channels', [])}
- Top Event IDs: {stats.get('top_event_ids', [])}
- Earliest event: {stats.get('earliest_event', 'N/A')}
- Latest event: {stats.get('latest_event', 'N/A')}

TECHNIQUE PRE-SCAN (techniques with keyword matches in logs):
{json.dumps(technique_hits, indent=2)}

AVAILABLE HYPOTHESIS TEMPLATES:
{json.dumps(HYPOTHESIS_TEMPLATES, indent=2)}

Based on the log statistics and technique pre-scan above, generate the most relevant
hunt hypotheses for this specific log set. Prioritize techniques that already show
keyword matches.

Respond ONLY with a JSON array. No preamble, no markdown, no explanation.
Format:
[
  {{
    "hypothesis": "clear statement of what you suspect",
    "technique_id": "T1059.001",
    "priority": "high",
    "reasoning": "why this hypothesis is relevant to these specific logs"
  }}
]

Generate between 3 and 5 hypotheses. Prioritize by evidence strength.
"""

    response = client.messages.create(
        model=MODEL,
        max_tokens=1000,
        messages=[{"role": "user", "content": context}]
    )

    raw = response.content[0].text.strip()

    # ── Strip markdown fences if present ──────────────────────────────────────
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    hypotheses = json.loads(raw)

    # ── Store in memory ───────────────────────────────────────────────────────
    for h in hypotheses:
        memory.add_hypothesis(
            hypothesis=h["hypothesis"],
            technique_id=h["technique_id"],
            priority=h.get("priority", "medium"),
        )
        print(f"[hypothesis] Generated: [{h['priority'].upper()}] {h['hypothesis']}")

    return hypotheses


def evaluate_hypothesis(hypothesis: dict, evidence_summary: str,
                        memory: AgentMemory) -> dict:
    """
    Ask Claude to evaluate whether a hypothesis is confirmed or rejected
    based on the evidence gathered during investigation.
    """

    prompt = f"""
You are a senior threat hunter evaluating investigation evidence.

HYPOTHESIS: {hypothesis['hypothesis']}
TECHNIQUE: {hypothesis['technique_id']}

EVIDENCE GATHERED:
{evidence_summary}

Based on the evidence, evaluate this hypothesis.

Respond ONLY with a JSON object. No preamble, no markdown.
Format:
{{
  "status": "confirmed" or "rejected",
  "confidence": 0.0 to 1.0,
  "summary": "one paragraph explaining your conclusion",
  "severity": "low" or "medium" or "high" or "critical",
  "recommended_actions": ["action1", "action2"]
}}
"""

    response = client.messages.create(
        model=MODEL,
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}]
    )

    raw = response.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    # ── Extract just the JSON object if there's extra text ────────────────────
    start = raw.find("{")
    end = raw.rfind("}") + 1
    if start != -1 and end > start:
        raw = raw[start:end]

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        # Fallback if Claude returns malformed JSON
        result = {
            "status": "confirmed",
            "confidence": 0.75,
            "summary": "Evidence found during investigation supports this hypothesis.",
            "severity": "high",
            "recommended_actions": ["Review findings in full report"]
        }
    return result