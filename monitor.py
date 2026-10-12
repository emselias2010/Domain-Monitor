import subprocess
import json

import os
DOMAIN = os.environ.get("PROTECTED_DOMAIN", "example.com")

print("=" * 60)
print("       DOMAIN MONITOR - V1")
print("=" * 60)
print(f"Protected domain: {DOMAIN}")
print()

command = [
    r".\venv\Scripts\python.exe",
    "-m",
    "dnstwist",
    "--format",
    "json",
    DOMAIN
]

print("[+] Starting dnstwist...")
print()

result = subprocess.run(
    command,
    capture_output=True,
    text=True
)

if result.returncode != 0:
    print("[!] dnstwist failed:")
    print(result.stderr)
    exit(1)

try:
    domains = json.loads(result.stdout)
except json.JSONDecodeError:
    print("[!] Could not read dnstwist output.")
    print(result.stdout)
    exit(1)

print(f"[+] Generated {len(domains)} domain candidates")
print()

for entry in domains:
    domain = entry.get("domain", "")
    
    if domain == DOMAIN:
        continue

    print(f"  {domain}")

print()
print("=" * 60)
print("Scan finished")
print("=" * 60)