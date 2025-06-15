import subprocess

# Define the P4 source files and corresponding output JSON files
p4_files = {
    "p4/l2switch-teste.p4": "json/l2switch-teste.json",
    "p4/ingress.p4": "json/ingress.json",
    "p4/label_forwarder.p4": "json/label_forwarder.json",
    "p4/teste_r4.p4": "json/teste_r4.json"
}

# Function to run a shell command and print output
def run_command(command):
    print(f"\nRunning: {command}")
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        print("✅ Success")
    else:
        print("❌ Failed")
        print(result.stderr)
    return result.returncode

# Compile all P4 programs
for p4_path, json_path in p4_files.items():
    cmd = f"p4c-bm2-ss --std p4-16 {p4_path} -o {json_path}"
    if run_command(cmd) != 0:
        print("Compilation failed. Aborting.")
        exit(1)