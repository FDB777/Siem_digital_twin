# SIEM Digital Twin — Beginner Project

A small, self-contained cybersecurity learning project that demonstrates how a Security Information and Event Management (SIEM) system and a digital twin can work together.

The project creates a fictional company network, generates normal and malicious security logs, detects an attack chain, estimates where the attack could spread next, and suggests the most important response actions.

> This is an educational simulation. It does not monitor a real network or provide production-grade security protection.

## What it does

The project models a simulated malware incident:

1. A user opens a malicious email attachment on a workstation.
2. The malware contacts an outside command-and-control server.
3. It moves to another workstation over SMB file sharing.
4. It steals credentials from memory.
5. It uses those credentials to access the domain controller.
6. It reaches the database server and transfers data out of the network.

The SIEM component finds the suspicious events in a larger collection of normal logs. The digital-twin component then simulates many possible infection paths through the network and ranks systems by likely business impact.

## Architecture

```text
Network topology
      │
      ▼
Generate normal logs + hidden attack
      │
      ▼
Rule-based SIEM detection and event correlation
      │
      ▼
Digital-twin spread simulation
      │
      ▼
Risk-based response recommendations and dashboard
```

## Technologies used

| Technology | Why it is used |
|---|---|
| Python 3 | Main programming language for simulation, detection, and analysis |
| Python standard library | `csv`, `json`, `random`, `datetime`, `re`, and `subprocess`; no extra packages are required |
| CSV | Stores generated logs, alerts, and prediction results in an easy-to-read format |
| JSON | Stores the simulated network topology |
| HTML, CSS, JavaScript | Creates a standalone interactive dashboard that opens in a browser |
| Monte Carlo simulation | Repeats thousands of possible outbreaks to estimate infection probability |

## Project files

| File | Purpose |
|---|---|
| `network_topology.py` | Defines the seven simulated devices and their network connections |
| `log_generator.py` | Creates 150 normal log events and 8 events representing a hidden attack |
| `correlation_engine.py` | Scores suspicious events and links related events into attack chains |
| `digital_twin.py` | Runs 5,000 simulated outbreaks and estimates which systems are at risk next |
| `recommend.py` | Produces simple response recommendations for the highest-impact systems |
| `build_dashboard.py` | Creates a standalone, searchable browser dashboard |
| `run_all.py` | Runs the five main pipeline steps in the correct order |

## Simulated network

The fictional organisation contains:

- `FW1` — edge firewall
- `WEB1` — public-facing web server
- `WS1`, `WS2`, `WS3` — employee workstations
- `DC1` — domain controller
- `DB1` — database server

Each device has a role, IP address, criticality score, patch/vulnerability value, and network connections. The digital twin uses the connections and device scores to model possible attack movement.

## How detection works

The SIEM uses simple, explainable detection rules. It raises a score for signals such as:

- double-extension filenames, for example `invoice.exe.scr`;
- credential-dumping tools or LSASS memory access;
- remote process creation and tools associated with lateral movement;
- suspicious Kerberos authentication requests;
- unusual interactive service-account use;
- large outbound data transfers.

Suspicious events are then correlated when they share a host and occur close together in time. This converts individual alerts into a readable attack story.

## How the digital twin works

The model starts from the first host identified in the strongest SIEM attack chain. For every simulation round, an infected system can attempt to infect its connected neighbours.

The probability of infection is based on:

- how easy the network route is assumed to be; and
- the target system's configured vulnerability value.

The model runs thousands of simulations, then calculates:

- **Infection probability** — how often a system becomes infected;
- **Average rounds to infection** — how quickly it is reached in successful simulations;
- **Criticality** — the business importance of the system;
- **Impact score** — `infection probability × criticality`.

Systems are ranked by impact score, not merely by chance of infection. This prioritises high-value assets such as the domain controller and database.

## Getting started

### Requirements

- Python 3.8 or later
- No third-party Python packages

### Run the complete analysis

From this project folder:

```bash
python run_all.py
```

This creates:

- `topology.json`
- `siem_logs.csv`
- `alerts.csv`
- `predicted_spread.csv`

### Build the dashboard

After running the pipeline:

```bash
python build_dashboard.py
```

Open `dashboard.html` in a browser. It includes high-severity alert cards, a searchable log table, predicted spread rankings, and recommended actions.

### Run individual stages

```bash
python network_topology.py
python log_generator.py
python correlation_engine.py
python digital_twin.py
python recommend.py
python build_dashboard.py
```

Run them in this order because each stage reads the file produced by the previous stage.

## Output files

| File | Contents |
|---|---|
| `topology.json` | Simulated systems and allowed network paths |
| `siem_logs.csv` | 158 generated log records: 150 routine events and 8 attack events |
| `alerts.csv` | Detected suspicious events, risk scores, and matching rules |
| `predicted_spread.csv` | Infection probability, criticality, impact score, and evaluation label for each host |
| `dashboard.html` | Standalone visual dashboard generated from the results |

## Advantages

- **Easy to understand:** the whole pipeline is small, readable, and uses only built-in Python modules.
- **Explainable results:** every alert includes the rules that caused it to be flagged.
- **Repeatable:** fixed random seeds make the demo results consistent between runs.
- **End-to-end example:** shows the connection between raw security telemetry, detection, correlation, prediction, and response.
- **No installation overhead:** no database, server, framework, or external Python dependency is needed.
- **Visual output:** the generated dashboard makes it easy to explore logs and risk predictions.

## Limitations

- **Not a real SIEM:** it does not ingest live Windows, firewall, cloud, EDR, or network logs.
- **Synthetic data only:** attack events and normal traffic are intentionally simplified.
- **Rule-based detection:** it uses fixed keywords and event types, so it cannot adapt to new attacker behaviour or learn a normal baseline.
- **Simplified propagation model:** network routes and infection probabilities are manually assigned rather than measured from a real environment.
- **No real-time response:** it cannot isolate devices, block IP addresses, reset accounts, or send alerts to analysts.
- **No persistence or access control:** data is stored in local files and the dashboard has no authentication, user roles, or audit trail.
- **Trusted-data dashboard:** the dashboard is suitable for this generated data. A production dashboard must safely escape untrusted log text before adding it to HTML.
- **Patch-level naming:** the current model uses the configured `patch_level` directly as a vulnerability input. In a real model, patch state and vulnerability should be represented separately and carefully.

## Possible next improvements

- Ingest real or realistic security telemetry such as Sysmon, Windows Event Logs, firewall logs, or Zeek logs.
- Store logs and alerts in a database such as Elasticsearch, OpenSearch, SQLite, or PostgreSQL.
- Add MITRE ATT&CK technique mappings to detections.
- Use threat-intelligence feeds and asset inventory data.
- Separate vulnerability, patch compliance, exposure, and privilege into distinct risk factors.
- Add alert thresholds, analyst workflow, authentication, and notification integrations.
- Replace the simple simulation with a graph-based or data-driven risk model.

#   S i e m _ d i g i t a l _ t w i n  
 