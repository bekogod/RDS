import subprocess

# Mapping of port numbers to flow files
flow_commands = {
    9090: "flows/s1-flows.txt",
    9091: "flows/r1-flows.txt",
    9092: "flows/r2-flows.txt",
    9093: "flows/r3-flows.txt",
    9094: "flows/r4-flows.txt",
    9095: "flows/r5-flows.txt",
    9096: "flows/r6-flows.txt"
}

# Function to run the CLI command
def run_flow_cmd(port, flow_file):
    cmd = f"simple_switch_CLI --thrift-port {port} < {flow_file}"
    print(f"\nApplying flows to port {port} from {flow_file}")
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        print("✅ Flow applied successfully.")
    else:
        print("❌ Failed to apply flows.")
        print(result.stderr)

# Run commands for all entries
for port, flow_file in flow_commands.items():
    run_flow_cmd(port, flow_file)
