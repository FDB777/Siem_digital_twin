# SIEM Digital Twin

An educational cybersecurity project that simulates a malware incident, detects suspicious activity with a simple SIEM, predicts possible attack spread, and displays the results in an interactive dashboard.

> This project uses fictional data only. It is a learning simulation, not a production SIEM.

## Features

- Builds a simulated company network with workstations, a firewall, web server, domain controller, and database.
- Generates 150 normal security events and 8 events that form a hidden malware attack.
- Detects suspicious activity with explainable, rule-based alerts.
- Correlates related alerts into an attack chain.
- Runs Monte Carlo simulations to estimate where an infection could spread.
- Ranks systems by business impact and recommends response actions.
- Generates a standalone browser dashboard with searchable logs and risk predictions.

## How it works

```text
Network topology
    -> Generate normal logs and attack events
    -> Detect and correlate suspicious events
    -> Simulate possible attack spread
    -> Rank risk and recommend actions
    -> Display results in a dashboard
```

## Simulated attack

The demo attack follows this sequence:

1. A user opens a malicious email attachment on `WS1`.
2. Malware makes an outbound command-and-control connection.
3. It moves to `WS2` through SMB file sharing.
4. It steals credentials from LSASS memory.
5. The stolen credentials are used against the domain controller (`DC1`).
6. The attacker reaches the database (`DB1`) and transfers data outside the network.

## Tech stack

| Technology | Use |
|---|---|
| Python 3 | Simulation, detection, prediction, and recommendations |
| Python standard library | CSV, JSON, regular expressions, timestamps, and random simulation |
| CSV and JSON | Input and output data storage |
| HTML, CSS, JavaScript | Standalone interactive dashboard |
| Monte Carlo simulation | Estimates infection probability across thousands of possible outbreaks |

No third-party Python packages are required.

## Project structure

| File | Description |
|---|---|
| `network_topology.py` | Defines the simulated devices and allowed connections. |
| `log_generator.py` | Generates normal logs plus the hidden attack chain. |
| `correlation_engine.py` | Scores suspicious events and correlates them into chains. |
| `digital_twin.py` | Simulates attack spread and calculates impact scores. |
| `recommend.py` | Suggests actions for the highest-risk systems. |
| `build_dashboard.py` | Creates the standalone `dashboard.html` page. |
| `run_all.py` | Runs the complete Python pipeline in order. |

## Run locally

### Requirements

- Python 3.8 or later

### Run the analysis

```bash
python run_all.py
```

This creates:

- `topology.json`
- `siem_logs.csv`
- `alerts.csv`
- `predicted_spread.csv`

### Build the dashboard

```bash
python build_dashboard.py
```

Open `dashboard.html` in a browser.

## Detection and risk model

The SIEM raises alerts for indicators such as suspicious double-extension filenames, credential dumping, remote process creation, suspicious Kerberos activity, unusual service-account use, and large outbound transfers.

Related alerts are connected when they involve the same host and occur close together in time. The digital twin then simulates infection attempts across the network. Each system receives an impact score:

```text
impact score = infection probability x system criticality
```

This gives priority to systems that are both likely to be affected and important to the organisation.

## Advantages

- Small, readable, beginner-friendly codebase.
- Every alert includes the reason it was detected.
- Reproducible results through fixed random seeds.
- Demonstrates the full path from security telemetry to response prioritisation.
- Works without a server, database, or external Python dependency.

## Limitations

- Does not collect or analyse real-time security logs.
- Uses synthetic events and manually assigned network-risk values.
- Detection rules are fixed and do not learn normal behaviour.
- The spread model is intentionally simplified and should not be used for real security decisions.
- The dashboard is static: visitors can explore results but cannot run the Python simulation online.

## Future improvements

- Add real log sources such as Sysmon, Windows Event Logs, firewall logs, or Zeek.
- Store data in a database or SIEM platform.
- Add MITRE ATT&CK mappings and threat-intelligence enrichment.
- Separate patch status, vulnerability, exposure, and privilege into distinct risk factors.
- Add a backend so visitors can run simulations with different scenarios.
