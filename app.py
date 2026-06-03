import json
import os
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG, GENERATED_REPORTS_DIR
from agent import run_agent
from report_generator import generate_report, save_report, save_markdown_report

app = Flask(__name__)

# ─── Global state ─────────────────────────────────────────────────────────────
agent_state = {
    "status": "idle",        # idle | running | complete | error
    "progress": [],          # Live log messages
    "memory": None,          # AgentMemory object
    "report": None,          # Generated report dict
    "report_path": None,     # Path to saved report
    "started_at": None,
    "completed_at": None,
}


def run_agent_thread():
    """Run the agent in a background thread so Flask stays responsive."""
    global agent_state
    agent_state["status"] = "running"
    agent_state["started_at"] = datetime.now().isoformat()
    agent_state["progress"] = []

    try:
        memory = run_agent()
        agent_state["memory"] = memory

        agent_state["progress"].append("Generating SOC incident report...")
        report = generate_report(memory)
        agent_state["report"] = report

        json_path = save_report(report, memory)
        md_path = save_markdown_report(report)
        agent_state["report_path"] = md_path

        agent_state["status"] = "complete"
        agent_state["completed_at"] = datetime.now().isoformat()
        agent_state["progress"].append("Investigation complete.")

    except Exception as e:
        agent_state["status"] = "error"
        agent_state["progress"].append(f"Error: {str(e)}")
        print(f"[app] Agent error: {e}")
        raise


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/start", methods=["POST"])
def start_hunt():
    global agent_state
    if agent_state["status"] == "running":
        return jsonify({"error": "Hunt already running"}), 400

    agent_state = {
        "status": "running",
        "progress": ["Starting autonomous threat hunt..."],
        "memory": None,
        "report": None,
        "report_path": None,
        "started_at": datetime.now().isoformat(),
        "completed_at": None,
    }

    thread = threading.Thread(target=run_agent_thread, daemon=True)
    thread.start()
    return jsonify({"status": "started"})


@app.route("/api/status")
def get_status():
    global agent_state
    memory_summary = None
    if agent_state["memory"]:
        memory_summary = agent_state["memory"].get_summary()

    return jsonify({
        "status": agent_state["status"],
        "progress": agent_state["progress"][-20:],
        "memory_summary": memory_summary,
        "started_at": agent_state["started_at"],
        "completed_at": agent_state["completed_at"],
    })


@app.route("/api/report")
def get_report():
    global agent_state
    if not agent_state["report"]:
        return jsonify({"error": "No report available yet"}), 404
    return jsonify(agent_state["report"])


@app.route("/api/memory")
def get_memory():
    global agent_state
    if not agent_state["memory"]:
        return jsonify({"error": "No memory available yet"}), 404
    return jsonify(json.loads(agent_state["memory"].to_json()))

@app.route("/api/trace")
def get_trace():
    global agent_state
    if not agent_state["memory"]:
        return jsonify({"error": "No trace available yet"}), 404
    memory = agent_state["memory"]
    
    # Build hypothesis-grouped trace
    trace = []
    for h in memory.hypotheses:
        # Find iterations related to this hypothesis
        h_iterations = []
        for log in memory.iteration_log:
            h_iterations.append({
                "iteration": log["iteration"],
                "thought": log["thought"][:200] if log["thought"] else "",
                "action": log["action"],
                "observation": log["observation"][:200],
                "timestamp": log["timestamp"],
            })
        
        trace.append({
            "hypothesis": h["hypothesis"],
            "technique_id": h["technique_id"],
            "priority": h["priority"],
            "status": h["status"],
            "confidence": h.get("confidence", 0),
            "iterations": h_iterations,
        })
    
    return jsonify({
        "trace": trace,
        "iteration_log": memory.iteration_log,
        "summary": memory.get_summary(),
    })

@app.route("/api/reports")
def list_reports():
    reports = []
    if os.path.exists(GENERATED_REPORTS_DIR):
        for f in sorted(os.listdir(GENERATED_REPORTS_DIR), reverse=True):
            if f.endswith(".json"):
                filepath = os.path.join(GENERATED_REPORTS_DIR, f)
                size = os.path.getsize(filepath)
                reports.append({
                    "filename": f,
                    "size": size,
                    "created": datetime.fromtimestamp(
                        os.path.getctime(filepath)
                    ).isoformat()
                })
    return jsonify(reports)


@app.route("/api/reports/<filename>")
def get_saved_report(filename):
    filepath = os.path.join(GENERATED_REPORTS_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "Report not found"}), 404
    with open(filepath) as f:
        return jsonify(json.load(f))


if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════════════╗
║     AUTONOMOUS THREAT HUNT AGENT — DASHBOARD         ║
║     http://localhost:{FLASK_PORT}                           ║
╚══════════════════════════════════════════════════════╝
    """)
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)