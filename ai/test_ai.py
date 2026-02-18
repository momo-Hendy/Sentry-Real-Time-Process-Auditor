import json
import subprocess
import sys

sample = {
    "pid": 1234,
    "name": "example.exe",
    "path": "C:\\Users\\User\\Downloads\\example.exe",
    "cmdline": "--silent",
    "ppid": 1,
    "timestamp": "2026-02-18T21:00:00-05:00",
}

proc = subprocess.run(
    [sys.executable, "-m", "ai.inference"],
    input=json.dumps(sample).encode("utf-8"),
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

print("STDERR:", proc.stderr.decode("utf-8"))
print("STDOUT:", proc.stdout.decode("utf-8"))