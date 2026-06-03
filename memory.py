import json
from datetime import datetime
from typing import Any


class AgentMemory:
    """
    The agent's memory system. Tracks everything the agent has
    investigated, found, and decided so it never repeats itself
    and can build on prior findings.
    """

    def __init__(self):
        self.session_start = datetime.now().isoformat()
        self.hypotheses = []        # Generated hunt hypotheses
        self.queries_run = []       # Every query the agent executed
        self.findings = []          # Confirmed suspicious findings
        self.false_positives = []   # Things investigated and cleared
        self.attack_timeline = []   # Chronological attack events
        self.confirmed_techniques = {}  # ATT&CK techniques confirmed
        self.iteration_log = []     # Full reasoning log per iteration

    # ─── Hypotheses ───────────────────────────────────────────────────────────

    def add_hypothesis(self, hypothesis: str, technique_id: str, priority: str = "medium"):
        entry = {
            "id": len(self.hypotheses) + 1,
            "hypothesis": hypothesis,
            "technique_id": technique_id,
            "priority": priority,
            "status": "pending",   # pending | confirmed | rejected
            "created_at": datetime.now().isoformat(),
        }
        self.hypotheses.append(entry)
        return entry["id"]

    def update_hypothesis_status(self, hypothesis_id: int, status: str, confidence: float = 0.0):
        for h in self.hypotheses:
            if h["id"] == hypothesis_id:
                h["status"] = status
                h["confidence"] = confidence
                h["updated_at"] = datetime.now().isoformat()
                break

    def get_pending_hypotheses(self):
        return [h for h in self.hypotheses if h["status"] == "pending"]

    # ─── Queries ──────────────────────────────────────────────────────────────

    def log_query(self, query_type: str, query: str, result_count: int, summary: str):
        entry = {
            "query_type": query_type,
            "query": query,
            "result_count": result_count,
            "summary": summary,
            "timestamp": datetime.now().isoformat(),
        }
        self.queries_run.append(entry)

    def already_queried(self, query: str) -> bool:
        return any(q["query"] == query for q in self.queries_run)

    # ─── Findings ─────────────────────────────────────────────────────────────

    def add_finding(self, title: str, description: str, technique_id: str,
                    severity: str, evidence: list, timestamp: str = None):
        entry = {
            "id": len(self.findings) + 1,
            "title": title,
            "description": description,
            "technique_id": technique_id,
            "severity": severity,       # low | medium | high | critical
            "evidence": evidence,
            "timestamp": timestamp or datetime.now().isoformat(),
        }
        self.findings.append(entry)
        self.confirmed_techniques[technique_id] = entry
        return entry["id"]

    def add_false_positive(self, description: str, reason: str):
        self.false_positives.append({
            "description": description,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
        })

    # ─── Timeline ─────────────────────────────────────────────────────────────

    def add_timeline_event(self, timestamp: str, event: str, technique_id: str, severity: str):
        self.attack_timeline.append({
            "timestamp": timestamp,
            "event": event,
            "technique_id": technique_id,
            "severity": severity,
        })
        self.attack_timeline.sort(key=lambda x: x["timestamp"])

    # ─── Iteration Log ────────────────────────────────────────────────────────

    def log_iteration(self, iteration: int, thought: str, action: str, observation: str):
        self.iteration_log.append({
            "iteration": iteration,
            "thought": thought,
            "action": action,
            "observation": observation,
            "timestamp": datetime.now().isoformat(),
        })

    # ─── Summary ──────────────────────────────────────────────────────────────

    def get_summary(self) -> dict:
        return {
            "session_start": self.session_start,
            "total_hypotheses": len(self.hypotheses),
            "confirmed_hypotheses": len([h for h in self.hypotheses if h["status"] == "confirmed"]),
            "rejected_hypotheses": len([h for h in self.hypotheses if h["status"] == "rejected"]),
            "total_queries": len(self.queries_run),
            "total_findings": len(self.findings),
            "false_positives": len(self.false_positives),
            "confirmed_techniques": list(self.confirmed_techniques.keys()),
            "attack_timeline_events": len(self.attack_timeline),
        }

    def to_json(self) -> str:
        return json.dumps({
            "summary": self.get_summary(),
            "hypotheses": self.hypotheses,
            "findings": self.findings,
            "attack_timeline": self.attack_timeline,
            "queries_run": self.queries_run,
            "iteration_log": self.iteration_log,
        }, indent=2)