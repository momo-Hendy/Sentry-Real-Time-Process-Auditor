import json
import subprocess
import sys
from pathlib import Path


def main() -> None:
    workspace = Path("/tmp/inference-smoke")
    workspace.mkdir(parents=True, exist_ok=True)

    audit_path = workspace / "audit.json"
    ledger_path = workspace / "monthly_audit.csv"
    state_path = workspace / ".offset"

    events = [
        {
            "severity": "LOW",
            "iso_ref": "ISO27001:A.12.4.1",
            "description": "Updated /etc/ssh/sshd_config",
            "timestamp": "2026-02-19T10:00:00Z",
        },
        {
            "severity": "LOW",
            "iso_ref": "ISO27001:A.12.4.1",
            "description": "Updated /etc/ssh/sshd_config during maintenance window",
            "timestamp": "2026-02-19T10:10:00Z",
        },
    ]

    with audit_path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "ai.inference",
            "--audit-path",
            str(audit_path),
            "--ledger-path",
            str(ledger_path),
            "--state-path",
            str(state_path),
            "--once",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    print("Return code:", proc.returncode)
    print("STDERR:", proc.stderr)
    print("Ledger contents:\n", ledger_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
