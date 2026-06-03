import os
import json
import glob
import re
from datetime import datetime
from typing import Any
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
import xml.etree.ElementTree as ET
from config import EVTX_LOG_DIR, TECHNIQUE_KEYWORDS


def load_evtx_file(filepath: str) -> list[dict]:
    """Parse an EVTX file and return a list of event dictionaries."""
    events = []
    try:
        with Evtx(filepath) as log:
            for xml_str, record in evtx_file_xml_view(log.chunks()):
                try:
                    root = ET.fromstring(xml_str)
                    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

                    # ── System fields ──────────────────────────────────────────
                    system = root.find("e:System", ns)
                    event_id = system.find("e:EventID", ns).text if system is not None else "unknown"
                    timestamp = system.find("e:TimeCreated", ns).attrib.get("SystemTime", "") if system is not None else ""
                    computer = system.find("e:Computer", ns).text if system is not None else ""
                    channel = system.find("e:Channel", ns).text if system is not None else ""

                    # ── EventData fields ───────────────────────────────────────
                    event_data = {}
                    data_section = root.find("e:EventData", ns)
                    if data_section is not None:
                        for data in data_section.findall("e:Data", ns):
                            name = data.attrib.get("Name", "Data")
                            event_data[name] = data.text or ""

                    events.append({
                        "event_id": event_id,
                        "timestamp": timestamp,
                        "computer": computer,
                        "channel": channel,
                        "data": event_data,
                        "raw": xml_str[:500],
                    })
                except Exception:
                    continue
    except Exception as e:
        print(f"[tools] Error loading {filepath}: {e}")
    return events


def get_all_events() -> list[dict]:
    """Load all EVTX files from the logs directory."""
    all_events = []
    evtx_files = glob.glob(os.path.join(EVTX_LOG_DIR, "**", "*.evtx"), recursive=True)
    json_files = glob.glob(os.path.join(EVTX_LOG_DIR, "**", "*.json"), recursive=True)

    for f in evtx_files:
        events = load_evtx_file(f)
        all_events.extend(events)
        print(f"[tools] Loaded {len(events)} events from {os.path.basename(f)}")

    for f in json_files:
        try:
            with open(f) as fh:
                data = json.load(fh)
                if isinstance(data, list):
                    all_events.extend(data)
                    print(f"[tools] Loaded {len(data)} events from {os.path.basename(f)}")
        except Exception as e:
            print(f"[tools] Error loading {f}: {e}")

    return all_events


def search_events_by_keyword(events: list[dict], keyword: str) -> list[dict]:
    """Search all events for a keyword (case-insensitive)."""
    keyword_lower = keyword.lower()
    matches = []
    for event in events:
        event_str = json.dumps(event).lower()
        if keyword_lower in event_str:
            matches.append(event)
    return matches


def search_events_by_id(events: list[dict], event_id: str) -> list[dict]:
    """Return all events matching a specific Windows Event ID."""
    return [e for e in events if str(e.get("event_id", "")) == str(event_id)]


def search_events_by_technique(events: list[dict], technique_id: str) -> list[dict]:
    """Search events for keywords associated with a MITRE ATT&CK technique."""
    keywords = TECHNIQUE_KEYWORDS.get(technique_id, [])
    matches = []
    seen = set()
    for keyword in keywords:
        results = search_events_by_keyword(events, keyword)
        for r in results:
            key = r.get("timestamp", "") + r.get("event_id", "")
            if key not in seen:
                seen.add(key)
                matches.append(r)
    return matches


def get_process_tree(events: list[dict], process_name: str) -> list[dict]:
    """Find all process creation events related to a process name."""
    matches = search_events_by_keyword(events, process_name)
    return [e for e in matches if e.get("event_id") in ["4688", "1"]]


def get_network_events(events: list[dict]) -> list[dict]:
    """Return all network connection events (Sysmon Event ID 3)."""
    return [e for e in events if e.get("event_id") == "3"]


def get_logon_events(events: list[dict]) -> list[dict]:
    """Return all logon/logoff events."""
    return [e for e in events if e.get("event_id") in ["4624", "4625", "4634", "4647"]]


def get_failed_logons(events: list[dict]) -> list[dict]:
    """Return failed logon attempts (Event ID 4625)."""
    return [e for e in events if e.get("event_id") == "4625"]


def get_scheduled_tasks(events: list[dict]) -> list[dict]:
    """Return scheduled task creation events."""
    return [e for e in events if e.get("event_id") in ["4698", "4702"]]


def get_registry_events(events: list[dict]) -> list[dict]:
    """Return registry modification events (Sysmon Event ID 13)."""
    return [e for e in events if e.get("event_id") == "13"]


def summarize_events(events: list[dict], max_events: int = 10) -> str:
    """Return a readable summary of a list of events for the agent."""
    if not events:
        return "No events found."
    summary_lines = [f"Found {len(events)} matching events. Showing top {min(max_events, len(events))}:\n"]
    for i, event in enumerate(events[:max_events]):
        data_preview = json.dumps(event.get("data", {}))[:200]
        summary_lines.append(
            f"[{i+1}] EventID={event.get('event_id')} | "
            f"Time={event.get('timestamp', 'N/A')[:19]} | "
            f"Host={event.get('computer', 'N/A')} | "
            f"Data={data_preview}"
        )
    return "\n".join(summary_lines)


def get_event_statistics(events: list[dict]) -> dict:
    """Return statistics about the loaded events."""
    if not events:
        return {"total": 0}

    event_id_counts = {}
    computers = set()
    channels = set()
    timestamps = []

    for e in events:
        eid = e.get("event_id", "unknown")
        event_id_counts[eid] = event_id_counts.get(eid, 0) + 1
        if e.get("computer"):
            computers.add(e["computer"])
        if e.get("channel"):
            channels.add(e["channel"])
        if e.get("timestamp"):
            timestamps.append(e["timestamp"])

    timestamps.sort()
    top_event_ids = sorted(event_id_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_events": len(events),
        "unique_hosts": list(computers),
        "channels": list(channels),
        "top_event_ids": top_event_ids,
        "earliest_event": timestamps[0] if timestamps else "N/A",
        "latest_event": timestamps[-1] if timestamps else "N/A",
    }