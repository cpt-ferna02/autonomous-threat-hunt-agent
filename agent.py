import json
import time
from anthropic import Anthropic
from config import ANTHROPIC_API_KEY, MODEL, MAX_ITERATIONS, CONFIDENCE_THRESHOLD
from memory import AgentMemory
from tools import (
    get_all_events,
    search_events_by_keyword,
    search_events_by_id,
    search_events_by_technique,
    get_process_tree,
    get_network_events,
    get_logon_events,
    get_failed_logons,
    get_scheduled_tasks,
    get_registry_events,
    summarize_events,
    get_event_statistics,
)
from hypothesis import generate_hypotheses, evaluate_hypothesis

client = Anthropic(api_key=ANTHROPIC_API_KEY)


# ─── Tool Definitions for Claude ──────────────────────────────────────────────
TOOLS = [
    {
        "name": "search_by_keyword",
        "description": "Search all events for a specific keyword. Use this to investigate suspicious strings, process names, commands, or usernames.",
        "input_schema": {
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": "The keyword to search for in all log events"
                }
            },
            "required": ["keyword"]
        }
    },
    {
        "name": "search_by_event_id",
        "description": "Search for events by Windows Event ID. Common IDs: 4624=Logon, 4625=Failed Logon, 4688=Process Creation, 4698=Scheduled Task, 1=Sysmon Process Create, 3=Sysmon Network, 13=Sysmon Registry",
        "input_schema": {
            "type": "object",
            "properties": {
                "event_id": {
                    "type": "string",
                    "description": "Windows Event ID to search for"
                }
            },
            "required": ["event_id"]
        }
    },
    {
        "name": "search_by_technique",
        "description": "Search events for all keywords associated with a MITRE ATT&CK technique ID.",
        "input_schema": {
            "type": "object",
            "properties": {
                "technique_id": {
                    "type": "string",
                    "description": "MITRE ATT&CK technique ID e.g. T1059.001"
                }
            },
            "required": ["technique_id"]
        }
    },
    {
        "name": "get_process_tree",
        "description": "Get all process creation events related to a specific process name.",
        "input_schema": {
            "type": "object",
            "properties": {
                "process_name": {
                    "type": "string",
                    "description": "Name of the process to investigate e.g. powershell.exe"
                }
            },
            "required": ["process_name"]
        }
    },
    {
        "name": "get_failed_logons",
        "description": "Get all failed logon attempts (Event ID 4625). Use to investigate brute force or credential attacks.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_network_events",
        "description": "Get all network connection events (Sysmon Event ID 3). Use to investigate lateral movement or C2 communication.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_scheduled_tasks",
        "description": "Get all scheduled task creation events (Event ID 4698/4702). Use to investigate persistence.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_registry_events",
        "description": "Get all registry modification events (Sysmon Event ID 13). Use to investigate persistence or defense evasion.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_logon_events",
        "description": "Get all logon and logoff events (4624, 4625, 4634). Use to investigate authentication patterns.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "confirm_finding",
        "description": "Confirm a suspicious finding and add it to the investigation report. Use when you have strong evidence of malicious activity.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Short title of the finding"
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of what was found"
                },
                "technique_id": {
                    "type": "string",
                    "description": "MITRE ATT&CK technique ID"
                },
                "severity": {
                    "type": "string",
                    "description": "Severity level: low, medium, high, or critical"
                },
                "evidence": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of evidence strings supporting this finding"
                }
            },
            "required": ["title", "description", "technique_id", "severity", "evidence"]
        }
    }
]


def execute_tool(tool_name: str, tool_input: dict, events: list[dict], memory: AgentMemory) -> str:
    """Execute a tool call and return the result as a string."""

    if tool_name == "search_by_keyword":
        keyword = tool_input["keyword"]
        if memory.already_queried(f"keyword:{keyword}"):
            return f"Already searched for '{keyword}' in this session. Try a different keyword."
        results = search_events_by_keyword(events, keyword)
        memory.log_query("keyword", f"keyword:{keyword}", len(results), f"Found {len(results)} events")
        return summarize_events(results)

    elif tool_name == "search_by_event_id":
        event_id = tool_input["event_id"]
        if memory.already_queried(f"event_id:{event_id}"):
            return f"Already searched for Event ID {event_id}. Try a different query."
        results = search_events_by_id(events, event_id)
        memory.log_query("event_id", f"event_id:{event_id}", len(results), f"Found {len(results)} events")
        return summarize_events(results)

    elif tool_name == "search_by_technique":
        technique_id = tool_input["technique_id"]
        if memory.already_queried(f"technique:{technique_id}"):
            return f"Already searched for technique {technique_id}. Try pivoting on specific keywords."
        results = search_events_by_technique(events, technique_id)
        memory.log_query("technique", f"technique:{technique_id}", len(results), f"Found {len(results)} events")
        return summarize_events(results)

    elif tool_name == "get_process_tree":
        process_name = tool_input["process_name"]
        results = get_process_tree(events, process_name)
        memory.log_query("process_tree", f"process:{process_name}", len(results), f"Found {len(results)} events")
        return summarize_events(results)

    elif tool_name == "get_failed_logons":
        results = get_failed_logons(events)
        memory.log_query("failed_logons", "failed_logons", len(results), f"Found {len(results)} failed logons")
        return summarize_events(results)

    elif tool_name == "get_network_events":
        results = get_network_events(events)
        memory.log_query("network", "network_events", len(results), f"Found {len(results)} network events")
        return summarize_events(results)

    elif tool_name == "get_scheduled_tasks":
        results = get_scheduled_tasks(events)
        memory.log_query("scheduled_tasks", "scheduled_tasks", len(results), f"Found {len(results)} scheduled task events")
        return summarize_events(results)

    elif tool_name == "get_registry_events":
        results = get_registry_events(events)
        memory.log_query("registry", "registry_events", len(results), f"Found {len(results)} registry events")
        return summarize_events(results)

    elif tool_name == "get_logon_events":
        results = get_logon_events(events)
        memory.log_query("logons", "logon_events", len(results), f"Found {len(results)} logon events")
        return summarize_events(results)

    elif tool_name == "confirm_finding":
        finding_id = memory.add_finding(
            title=tool_input.get("title", "Untitled Finding"),
            description=tool_input.get("description", "No description provided"),
            technique_id=tool_input.get("technique_id", "T0000"),
            severity=tool_input.get("severity", "medium"),
            evidence=tool_input.get("evidence", []),
        )
        memory.add_timeline_event(
            timestamp=__import__('datetime').datetime.now().isoformat(),
            event=tool_input.get("title", "Untitled Finding"),
            technique_id=tool_input.get("technique_id", "T0000"),
            severity=tool_input.get("severity", "medium"),
        )
        return f"Finding #{finding_id} confirmed and added to report: {tool_input.get('title', 'Untitled Finding')}"

    return f"Unknown tool: {tool_name}"


def run_agent(log_source: str = None) -> AgentMemory:
    """
    Main agent loop. Loads events, generates hypotheses,
    then runs the ReAct loop to investigate autonomously.
    """

    memory = AgentMemory()
    print("\n" + "="*60)
    print("  AUTONOMOUS THREAT HUNT AGENT — STARTING")
    print("="*60)

    # ── Step 1: Load events ────────────────────────────────────────────────────
    print("\n[agent] Loading events from logs directory...")
    events = get_all_events()

    if not events:
        print("[agent] No events found in logs directory.")
        print("[agent] Please add .evtx or .json log files to the logs/ folder.")
        return memory

    stats = get_event_statistics(events)
    print(f"[agent] Loaded {stats['total_events']} events from {stats['unique_hosts']}")

    # ── Step 2: Generate hypotheses ────────────────────────────────────────────
    print("\n[agent] Generating hunt hypotheses...")
    hypotheses = generate_hypotheses(events, memory)
    print(f"[agent] Generated {len(hypotheses)} hypotheses")

    # ── Step 3: ReAct loop ─────────────────────────────────────────────────────
    print("\n[agent] Starting autonomous investigation...\n")

    messages = [
        {
            "role": "user",
            "content": f"""You are an autonomous threat hunting agent investigating Windows security logs.

LOADED LOG STATISTICS:
{json.dumps(stats, indent=2)}

HUNT HYPOTHESES TO INVESTIGATE:
{json.dumps(hypotheses, indent=2)}

Your job:
1. Investigate each hypothesis systematically using the available tools
2. Search for evidence supporting or refuting each hypothesis
3. Pivot on findings — if you find something suspicious, dig deeper
4. When you find confirmed malicious activity, use confirm_finding to record it
5. Do not repeat the same query twice
6. After investigating all hypotheses, say INVESTIGATION COMPLETE

Start investigating now. Think step by step.
"""
        }
    ]

    iteration = 0

    while iteration < MAX_ITERATIONS:
        iteration += 1
        print(f"\n[agent] ── Iteration {iteration}/{MAX_ITERATIONS} ──")

        response = client.messages.create(
            model=MODEL,
            max_tokens=1500,
            tools=TOOLS,
            messages=messages,
        )

        # ── Extract text thoughts ──────────────────────────────────────────────
        thought = ""
        for block in response.content:
            if hasattr(block, "text"):
                thought = block.text
                if thought:
                    print(f"\n[agent] THOUGHT: {thought[:300]}{'...' if len(thought) > 300 else ''}")

        # ── Check stop conditions ──────────────────────────────────────────────
        if response.stop_reason == "end_turn":
            if "INVESTIGATION COMPLETE" in thought:
                print("\n[agent] Agent signaled investigation complete.")
                break
            if iteration >= MAX_ITERATIONS:
                print("\n[agent] Max iterations reached.")
                break

        # ── Process tool calls ─────────────────────────────────────────────────
        tool_calls_made = False
        tool_results = []

        for block in response.content:
            if block.type == "tool_use":
                tool_calls_made = True
                tool_name = block.name
                tool_input = block.input

                print(f"[agent] ACTION: {tool_name}({json.dumps(tool_input)[:100]})")

                observation = execute_tool(tool_name, tool_input, events, memory)
                print(f"[agent] OBSERVATION: {observation[:200]}{'...' if len(observation) > 200 else ''}")

                memory.log_iteration(
                    iteration=iteration,
                    thought=thought,
                    action=f"{tool_name}({json.dumps(tool_input)[:150]})",
                    observation=observation[:300]
                )

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": observation,
                })

        # ── Update message history ─────────────────────────────────────────────
        messages.append({"role": "assistant", "content": response.content})

        if tool_results:
            messages.append({"role": "user", "content": tool_results})

        if not tool_calls_made and response.stop_reason == "end_turn":
            print("\n[agent] No more tool calls. Investigation complete.")
            break

        time.sleep(0.5)

    # ── Step 4: Evaluate hypotheses ────────────────────────────────────────────
    print("\n[agent] Evaluating hypotheses against findings...")
    findings_summary = json.dumps(memory.findings, indent=2) if memory.findings else "No findings confirmed."

    for h in memory.hypotheses:
        result = evaluate_hypothesis(h, findings_summary, memory)
        memory.update_hypothesis_status(
            h["id"],
            result.get("status", "rejected"),
            result.get("confidence", 0.0)
        )
        status_icon = "✅" if result["status"] == "confirmed" else "❌"
        print(f"[agent] {status_icon} {h['hypothesis'][:60]} — {result['status'].upper()} ({result['confidence']:.0%})")

    # ── Final summary ──────────────────────────────────────────────────────────
    summary = memory.get_summary()
    print("\n" + "="*60)
    print("  INVESTIGATION SUMMARY")
    print("="*60)
    print(f"  Hypotheses tested : {summary['total_hypotheses']}")
    print(f"  Confirmed         : {summary['confirmed_hypotheses']}")
    print(f"  Rejected          : {summary['rejected_hypotheses']}")
    print(f"  Total queries     : {summary['total_queries']}")
    print(f"  Findings          : {summary['total_findings']}")
    print(f"  ATT&CK techniques : {summary['confirmed_techniques']}")
    print("="*60)

    return memory