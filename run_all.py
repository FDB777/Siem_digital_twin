import subprocess

steps_in_order = [
    "network_topology.py",   # Step 1: build the fake network
    "log_generator.py",      # Step 2: create fake logs (with a hidden attack)
    "correlation_engine.py", # Step 3: find the attack in the logs
    "digital_twin.py",       # Step 4: predict what happens next
    "recommend.py",          # Step 5: suggest what to do about it
]

for step_file in steps_in_order:
    print(f"\n----- Running {step_file} -----")
    subprocess.run(["python", step_file], check=True)

print("\nAll done! Check the folder for these new files:")
print("  topology.json, siem_logs.csv, alerts.csv, predicted_spread.csv")
