import csv
import json
import random
from datetime import datetime

from correlation_engine import connect_alerts_into_chains

NUMBER_OF_SIMULATIONS = 5000
MAX_ROUNDS = 6


def build_connections_map(topology):
    connections = {}
    for node in topology["nodes"]:
        connections[node["id"]] = []  # start with an empty list for every node

    for source, target, ease, channel_name in topology["edges"]:
        connections[source].append((target, ease))
        connections[target].append((source, ease * 0.6))

    return connections


def chance_of_infecting(ease_of_travel, target_vulnerability):
    probability = 0.5 * ease_of_travel + 0.5 * target_vulnerability
    if probability > 1.0:
        probability = 1.0
    if probability < 0.0:
        probability = 0.0
    return probability


def simulate_one_outbreak(seed_node, connections, vulnerability_by_node, random_generator):
    infected_at_round = {seed_node: 0}
    currently_infected = [seed_node]

    for round_number in range(1, MAX_ROUNDS + 1):
        newly_infected_this_round = []

        for infected_node in currently_infected:
            for neighbor_node, ease in connections[infected_node]:
                if neighbor_node in infected_at_round:
                    continue  # already infected, skip

                probability = chance_of_infecting(ease, vulnerability_by_node[neighbor_node])
                if random_generator.random() < probability:
                    if neighbor_node not in newly_infected_this_round:
                        newly_infected_this_round.append(neighbor_node)

        if len(newly_infected_this_round) == 0:
            break  # nothing new got infected, the outbreak has stopped

        for node in newly_infected_this_round:
            infected_at_round[node] = round_number
        currently_infected = newly_infected_this_round

    return infected_at_round


def find_seed_from_siem_results():
    with open("alerts.csv", newline="") as file:
        alerts = list(csv.DictReader(file))

    chains = connect_alerts_into_chains(alerts)
    if len(chains) == 0:
        raise RuntimeError("No attack chain found in alerts.csv -- run correlation_engine.py first.")
    best_chain = max(chains, key=lambda chain: sum(int(a["alert_score"]) for a in chain))
    first_step = best_chain[0]
    seed_hostname = first_step["dst_host"] or first_step["src_host"]

    touched_hostnames = set()
    for chain in chains:
        for step in chain:
            if step["src_host"]:
                touched_hostnames.add(step["src_host"])
            if step["dst_host"]:
                touched_hostnames.add(step["dst_host"])

    return seed_hostname, touched_hostnames


if __name__ == "__main__":
    with open("topology.json") as file:
        topology = json.load(file)
    hostname_to_id = {}
    vulnerability_by_node = {}
    criticality_by_node = {}
    for node in topology["nodes"]:
        hostname_to_id[node["hostname"]] = node["id"]
        vulnerability_by_node[node["id"]] = node["patch_level"]
        criticality_by_node[node["id"]] = node["criticality"]

    connections = build_connections_map(topology)

    seed_hostname, touched_hostnames = find_seed_from_siem_results()
    seed_node = hostname_to_id[seed_hostname]

    actually_infected_nodes = set()
    for hostname in touched_hostnames:
        if hostname in hostname_to_id:
            actually_infected_nodes.add(hostname_to_id[hostname])
    actually_infected_nodes.discard(seed_node)

    print(f"Seed computer (picked automatically from the SIEM's results): {seed_node}\n")
    random_generator = random.Random(7)
    times_infected = {}  
    round_totals = {}     

    for node_id in vulnerability_by_node:
        times_infected[node_id] = 0
        round_totals[node_id] = 0

    for simulation_number in range(NUMBER_OF_SIMULATIONS):
        result = simulate_one_outbreak(seed_node, connections, vulnerability_by_node, random_generator)
        for node_id, round_infected in result.items():
            if node_id != seed_node:
                times_infected[node_id] += 1
                round_totals[node_id] += round_infected
    results_table = []
    for node_id in vulnerability_by_node:
        if node_id == seed_node:
            continue

        infection_probability = times_infected[node_id] / NUMBER_OF_SIMULATIONS
        criticality = criticality_by_node[node_id]
        impact_score = infection_probability * criticality

        if times_infected[node_id] > 0:
            average_round = round_totals[node_id] / times_infected[node_id]
        else:
            average_round = None

        results_table.append({
            "node": node_id,
            "infection_probability": round(infection_probability, 3),
            "avg_rounds_to_infection": round(average_round, 2) if average_round is not None else "",
            "criticality": criticality,
            "impact_score": round(impact_score, 3),
            "actually_hit": node_id in actually_infected_nodes,
        })
    results_table.sort(key=lambda row: row["impact_score"], reverse=True)
    print(f"{'Node':<6}{'P(infected)':<14}{'Avg rounds':<13}{'Criticality':<13}{'Impact':<9}{'Actually hit?'}")
    for row in results_table:
        print(f"{row['node']:<6}{row['infection_probability']:<14}{str(row['avg_rounds_to_infection']):<13}"
              f"{row['criticality']:<13}{row['impact_score']:<9}{row['actually_hit']}")
    with open("predicted_spread.csv", "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(results_table[0].keys()))
        writer.writeheader()
        writer.writerows(results_table)

    top_n = results_table[:len(actually_infected_nodes)]
    predicted_nodes = set(row["node"] for row in top_n)
    correct_predictions = predicted_nodes & actually_infected_nodes

    if len(predicted_nodes) > 0:
        precision = len(correct_predictions) / len(predicted_nodes)
    else:
        precision = 0
    if len(actually_infected_nodes) > 0:
        recall = len(correct_predictions) / len(actually_infected_nodes)
    else:
        recall = 0

    print("\nSaved predicted_spread.csv")
    print("\nHow good was the prediction?")
    print(f"  Actually infected (per the SIEM): {sorted(actually_infected_nodes)}")
    print(f"  Twin predicted top {len(predicted_nodes)}:         {sorted(predicted_nodes)}")
    print(f"  Correctly predicted: {sorted(correct_predictions)}")
    print(f"  Precision = {precision:.2f}, Recall = {recall:.2f}")
