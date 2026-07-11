"""
The attack story, in plain English:
  1. Someone opens a bad email attachment on their computer (WS1).
  2. That malware "calls home" to the attacker over the internet.
  3. The malware spreads to a second computer (WS2) over the network.
  4. It steals login credentials that are stored in memory on WS2.
  5. It uses those stolen credentials to log into the Domain Controller.
  6. From there, it reaches the Database server.
  7. It copies a large amount of data out of the database (theft!).
"""

import csv
import json
import random
from datetime import datetime, timedelta

random.seed(42)
with open("topology.json") as file:
    topology = json.load(file)
NODES_BY_ID = {}
for node in topology["nodes"]:
    NODES_BY_ID[node["id"]] = node

ALL_NODE_IDS = list(NODES_BY_ID.keys())
USER_NAMES = ["j.smith", "a.patel", "m.oconnor", "svc_backup", "r.chen"]
ATTACK_START_TIME = datetime(2026, 7, 1, 10, 0, 0)  # 10:00 AM


def make_log_row(when, source_node_id, target_node_id, user, event_type, process_name, port, severity, description):
    source_info = NODES_BY_ID.get(source_node_id)
    target_info = NODES_BY_ID.get(target_node_id)

    row = {
        "timestamp": when.isoformat(),
        "src_ip": source_info["ip"] if source_info else "",
        "src_host": source_info["hostname"] if source_info else "",
        "dst_ip": target_info["ip"] if target_info else "",
        "dst_host": target_info["hostname"] if target_info else "",
        "user": user,
        "event_type": event_type,
        "process": process_name,
        "port": port,
        "protocol": "tcp" if port else "",
        "severity": severity,
        "description": description,
    }
    return row


def build_attack_chain():
    rows = []

    rows.append(make_log_row(
        ATTACK_START_TIME + timedelta(minutes=0),
        None, "WS1", "j.smith", "process_creation", "invoice_march.exe.scr", None,
        "high", "Suspicious double-extension executable launched from email attachment"))

    rows.append(make_log_row(
        ATTACK_START_TIME + timedelta(minutes=3),
        "WS1", "FW1", "j.smith", "network_connection", "invoice_march.exe.scr", 443,
        "high", "Beacon-like outbound connection to unfamiliar external host (C2 check-in)"))

    rows.append(make_log_row(
        ATTACK_START_TIME + timedelta(minutes=15),
        "WS1", "WS2", "j.smith", "smb_session", "invoice_march.exe.scr", 445,
        "medium", "SMB session established to shared folder on ws-hr-02"))

    rows.append(make_log_row(
        ATTACK_START_TIME + timedelta(minutes=19),
        "WS1", "WS2", "j.smith", "remote_process_creation", "svchost32.exe", 445,
        "high", "Remote process creation on ws-hr-02 originating from ws-finance-01"))

    rows.append(make_log_row(
        ATTACK_START_TIME + timedelta(minutes=27),
        "WS2", None, "SYSTEM", "credential_access", "lsass_dump.exe", None,
        "critical", "LSASS memory access consistent with credential dumping"))

    rows.append(make_log_row(
        ATTACK_START_TIME + timedelta(minutes=33),
        "WS2", "DC1", "a.patel", "kerberos_auth", "lsass_dump.exe", 88,
        "critical", "Anomalous Kerberos ticket request using a.patel's credentials"))

    rows.append(make_log_row(
        ATTACK_START_TIME + timedelta(minutes=43),
        "DC1", "DB1", "svc_backup", "service_account_login", "psexec.exe", 445,
        "critical", "Service account used interactively from domain controller"))

    rows.append(make_log_row(
        ATTACK_START_TIME + timedelta(minutes=58),
        "DB1", None, "svc_backup", "large_data_transfer", "curl.exe", 443,
        "critical", "Large outbound data transfer (2.3 GB) to external IP"))

    return rows


def build_background_noise(how_many=150):
    """
    Creates a bunch of normal, boring log rows -- logins, DNS lookups,
    file access, web browsing. This is the "noise" that a real SIEM
    has to sift through to find the real attack.
    """
    kinds_of_events = {
        "login_success": ("winlogon.exe", 445),
        "dns_query":      ("svchost.exe", 53),
        "file_access":    ("explorer.exe", 445),
        "http_request":   ("chrome.exe", 443),
    }

    rows = []
    for _ in range(how_many):
        source_id = random.choice(ALL_NODE_IDS)
        target_id = random.choice(ALL_NODE_IDS)
        while target_id == source_id:
            target_id = random.choice(ALL_NODE_IDS)

        kind = random.choice(list(kinds_of_events.keys()))
        process_name, port = kinds_of_events[kind]
        user = random.choice(USER_NAMES)
        random_seconds = random.randint(0, 8 * 3600)
        when = ATTACK_START_TIME.replace(hour=8, minute=0, second=0) + timedelta(seconds=random_seconds)

        source_host = NODES_BY_ID[source_id]["hostname"]
        target_host = NODES_BY_ID[target_id]["hostname"]
        description = f"Routine {kind.replace('_', ' ')} from {source_host} to {target_host}"

        rows.append(make_log_row(when, source_id, target_id, user, kind, process_name, port, "info", description))

    return rows


if __name__ == "__main__":
    all_rows = build_background_noise(150) + build_attack_chain()
    all_rows.sort(key=lambda row: row["timestamp"])

    column_names = list(all_rows[0].keys())
    with open("siem_logs.csv", "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=column_names)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"Done! Saved siem_logs.csv with {len(all_rows)} total log rows")
    print("  (150 are normal/boring, 8 are the hidden attack)")
