import csv
import json
RECOMMENDED_ACTIONS = {
    "domain_controller": "Force everyone to change their passwords; turn on extra login logging.",
    "database":           "Limit this account to read-only access; watch closely for large data transfers.",
    "workstation":        "Disconnect this computer from the network and check its memory for evidence.",
    "web_server":         "Check the web server's security logs for how it was broken into; change its passwords.",
    "firewall":           "Block the suspicious outside connection; review what's allowed to leave the network.",
}
HOW_MANY_TO_SHOW = 3
if __name__ == "__main__":
    with open("topology.json") as file:
        topology = json.load(file)

    role_by_node = {}
    for node in topology["nodes"]:
        role_by_node[node["id"]] = node["role"]

    with open("predicted_spread.csv", newline="") as file:
        rows = list(csv.DictReader(file))

    # Sort by impact_score, biggest first.
    rows.sort(key=lambda row: float(row["impact_score"]), reverse=True)
    top_rows = rows[:HOW_MANY_TO_SHOW]

    print(f"Top {HOW_MANY_TO_SHOW} things to fix first:\n")
    for row in top_rows:
        node_id = row["node"]
        role = role_by_node[node_id]
        action = RECOMMENDED_ACTIONS.get(role, "Disconnect it and investigate.")

        print(f"{node_id} ({role})")
        print(f"  Chance of being infected: {row['infection_probability']}")
        print(f"  Impact score: {row['impact_score']}")
        print(f"  Suggested action: {action}\n")
