import csv
import re
from datetime import datetime, timedelta
CHAIN_TIME_LIMIT = timedelta(minutes=30)
DOUBLE_EXTENSION_PATTERN = re.compile(r"\.\w{2,4}\.\w{2,4}$")

CREDENTIAL_THEFT_WORDS = ["lsass", "mimikatz", "dump", "secretsdump"]
LATERAL_MOVEMENT_WORDS = ["psexec", "wmic", "smbexec"]


def check_row_for_problems(row):
    process_name = (row["process"] or "").lower()
    score = 0
    reasons = []

    if DOUBLE_EXTENSION_PATTERN.search(row["process"] or ""):
        score += 6
        reasons.append("Double-extension filename suggests malware disguise")

    if row["event_type"] == "credential_access":
        score += 9
        reasons.append("Direct credential-theft event (reading passwords from memory)")

    for bad_word in CREDENTIAL_THEFT_WORDS:
        if bad_word in process_name:
            score += 8
            reasons.append("Process name matches a known credential-theft tool")
            break  # only count this rule once per row

    for bad_word in LATERAL_MOVEMENT_WORDS:
        if bad_word in process_name:
            score += 7
            reasons.append("Process name matches a known network-spreading tool")
            break

    if row["event_type"] == "remote_process_creation":
        score += 7
        reasons.append("A program was started remotely on another computer (spreading)")

    if row["event_type"] == "service_account_login" and process_name not in ("", "svchost.exe"):
        score += 8
        reasons.append("A service account was used interactively (it normally shouldn't be)")

    if row["event_type"] == "kerberos_auth":
        score += 7
        reasons.append("Suspicious login-ticket request")

    if row["event_type"] == "large_data_transfer":
        score += 9
        reasons.append("Large amount of data leaving the network (possible theft)")

    return score, reasons


def find_all_alerts(all_log_rows):
    alerts = []
    for row in all_log_rows:
        score, reasons = check_row_for_problems(row)
        if score > 0:
            alert = dict(row) 
            alert["alert_score"] = score
            alert["matched_rules"] = " | ".join(reasons)
            alerts.append(alert)
    return alerts


def connect_alerts_into_chains(alerts):
    sorted_alerts = sorted(alerts, key=lambda a: a["timestamp"])

    chains = []
    already_used = [False] * len(sorted_alerts)

    for i in range(len(sorted_alerts)):
        if already_used[i]:
            continue

        current_chain = [sorted_alerts[i]]
        already_used[i] = True
        involved_hosts = {sorted_alerts[i]["src_host"], sorted_alerts[i]["dst_host"]}
        last_time = datetime.fromisoformat(sorted_alerts[i]["timestamp"])
        for j in range(i + 1, len(sorted_alerts)):
            if already_used[j]:
                continue

            candidate = sorted_alerts[j]
            candidate_time = datetime.fromisoformat(candidate["timestamp"])

            if candidate_time - last_time > CHAIN_TIME_LIMIT:
                continue  

            if candidate["src_host"] in involved_hosts or candidate["dst_host"] in involved_hosts:
                current_chain.append(candidate)
                involved_hosts.add(candidate["src_host"])
                involved_hosts.add(candidate["dst_host"])
                last_time = candidate_time
                already_used[j] = True
        if len(current_chain) > 1:
            chains.append(current_chain)

    return chains


if __name__ == "__main__":
    with open("siem_logs.csv", newline="") as file:
        log_rows = list(csv.DictReader(file))

    alerts = find_all_alerts(log_rows)
    print(f"Scanned {len(log_rows)} log rows.")
    print(f"Flagged {len(alerts)} of them as suspicious.\n")

    # save the alerts to a file
    column_names = list(alerts[0].keys())
    with open("alerts.csv", "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=column_names)
        writer.writeheader()
        writer.writerows(alerts)

    chains = connect_alerts_into_chains(alerts)
    chains.sort(key=lambda chain: sum(int(a["alert_score"]) for a in chain), reverse=True)

    print(f"Reconstructed {len(chains)} attack chain(s):\n")
    for chain_number, chain in enumerate(chains, start=1):
        total_score = sum(int(a["alert_score"]) for a in chain)
        print(f"=== Chain #{chain_number} ({len(chain)} steps, total risk score {total_score}) ===")
        for step in chain:
            source = step["src_host"] or "-"
            target = step["dst_host"] or "-"
            print(f"  [{step['timestamp']}] {source} -> {target}  (score {step['alert_score']})")
            print(f"      why: {step['matched_rules']}")
        print()
