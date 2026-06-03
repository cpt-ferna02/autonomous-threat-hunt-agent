import os

# ─── Anthropic ────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
MODEL = "claude-haiku-4-5"

# ─── Agent Settings ───────────────────────────────────────────────────────────
MAX_ITERATIONS = 10        # Max reasoning steps before the agent stops
MAX_HYPOTHESES = 5         # Max hypotheses the agent can generate
CONFIDENCE_THRESHOLD = 0.7 # Minimum confidence to confirm a hypothesis

# ─── Log Sources ──────────────────────────────────────────────────────────────
EVTX_LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
GENERATED_REPORTS_DIR = os.path.join(os.path.dirname(__file__), "generated_reports")

# ─── MITRE ATT&CK Technique Keywords ──────────────────────────────────────────
TECHNIQUE_KEYWORDS = {
    "T1059.001": ["powershell", "pwsh", "System.Management.Automation"],
    "T1059.003": ["cmd.exe", "command prompt", "cmd /c"],
    "T1053.005": ["schtasks", "scheduled task", "Task Scheduler"],
    "T1003.001": ["lsass", "mimikatz", "sekurlsa", "procdump"],
    "T1082":     ["systeminfo", "hostname", "whoami", "net user"],
    "T1110.001": ["failed logon", "logon failure", "4625"],
    "T1562.001": ["defender", "DisableRealtimeMonitoring", "Set-MpPreference"],
    "T1021.002": ["net use", "\\\\", "SMB", "lateral movement"],
    "T1055":     ["process inject", "VirtualAlloc", "WriteProcessMemory"],
    "T1136.001": ["net user /add", "useradd", "New-LocalUser"],
    "T1547.001": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "registry run key"],
    "T1070.001": ["wevtutil", "Clear-EventLog", "event log cleared"],
}

# ─── Hunt Hypothesis Templates ────────────────────────────────────────────────
HYPOTHESIS_TEMPLATES = [
    "There may be PowerShell abuse for command execution (T1059.001)",
    "There may be credential dumping activity targeting LSASS (T1003.001)",
    "There may be persistence mechanisms via scheduled tasks (T1053.005)",
    "There may be lateral movement via SMB/network shares (T1021.002)",
    "There may be defense evasion by disabling security tools (T1562.001)",
    "There may be reconnaissance activity via system discovery (T1082)",
    "There may be brute force or password guessing activity (T1110.001)",
    "There may be process injection techniques in use (T1055)",
    "There may be new user accounts being created (T1136.001)",
    "There may be log tampering or evidence clearing (T1070.001)",
]

# ─── Flask ─────────────────────────────────────────────────────────────────────
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
FLASK_DEBUG = False