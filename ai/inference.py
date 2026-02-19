from __future__ import annotations

import argparse
import csv
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


DEFAULT_AUDIT_PATH = "/app/logs/audit.json"
DEFAULT_LEDGER_PATH = "/logs/monthly_audit.csv"
DEFAULT_STATE_PATH = "/logs/.inference.offset"
POLL_INTERVAL_SECONDS = 1.0


@dataclass
class Verdict:
    verdict: str
    reason: str


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_offset(state_path: Path) -> int:
    if not state_path.exists():
        return 0

    try:
        return max(0, int(state_path.read_text(encoding="utf-8").strip() or "0"))
    except ValueError:
        return 0


def _write_offset(state_path: Path, offset: int) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(str(max(0, offset)), encoding="utf-8")


def _safe_json_loads(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None

    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    return payload


def _description_mentions_etc(description: str) -> bool:
    return "/etc" in description.lower()


def _admin_session_active(event: Dict[str, Any]) -> bool:
    """
    Heuristic for demo purposes.
    Accept explicit boolean `admin_session_active` if producer provides it.
    Otherwise look for markers in free-text description.
    """
    direct_flag = event.get("admin_session_active")
    if isinstance(direct_flag, bool):
        return direct_flag

    description = str(event.get("description", "")).lower()
    active_markers = (
        "admin session active",
        "authorized admin",
        "change window approved",
        "maintenance window",
    )
    return any(marker in description for marker in active_markers)


def classify_event(event: Dict[str, Any]) -> Verdict:
    severity = str(event.get("severity", "unknown")).upper()
    description = str(event.get("description", ""))

    if _description_mentions_etc(description) and not _admin_session_active(event):
        return Verdict(
            verdict="MALICIOUS",
            reason="/etc change detected without an active admin session",
        )

    if severity in {"CRITICAL", "HIGH"}:
        return Verdict(
            verdict="MALICIOUS",
            reason=f"Event severity is {severity}",
        )

    return Verdict(
        verdict="AUTHORIZED",
        reason="No policy violation detected by inference rules",
    )


def _ledger_headers() -> list[str]:
    return [
        "timestamp",
        "severity",
        "iso_ref",
        "description",
        "event_timestamp",
        "ai_verdict",
        "ai_reason",
    ]


def _append_ledger_row(ledger_path: Path, event: Dict[str, Any], verdict: Verdict) -> None:
    ledger_path.parent.mkdir(parents=True, exist_ok=True)

    row = {
        "timestamp": _utc_now_iso(),
        "severity": str(event.get("severity", "")),
        "iso_ref": str(event.get("iso_ref", "")),
        "description": str(event.get("description", "")),
        "event_timestamp": str(event.get("timestamp", "")),
        "ai_verdict": verdict.verdict,
        "ai_reason": verdict.reason,
    }

    exists = ledger_path.exists()
    with ledger_path.open("a", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=_ledger_headers())
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def _iter_new_events(audit_path: Path, state_path: Path) -> Iterable[Dict[str, Any]]:
    if not audit_path.exists():
        return

    last_offset = _read_offset(state_path)
    file_size = audit_path.stat().st_size
    if file_size < last_offset:
        # File rotated or truncated.
        last_offset = 0

    with audit_path.open("r", encoding="utf-8") as audit_file:
        audit_file.seek(last_offset)

        while True:
            line = audit_file.readline()
            if not line:
                _write_offset(state_path, audit_file.tell())
                break

            payload = _safe_json_loads(line)
            if payload is None:
                _write_offset(state_path, audit_file.tell())
                continue

            _write_offset(state_path, audit_file.tell())
            yield payload


def process_new_events(audit_path: Path, ledger_path: Path, state_path: Path) -> int:
    processed = 0
    for event in _iter_new_events(audit_path, state_path):
        verdict = classify_event(event)
        _append_ledger_row(ledger_path, event, verdict)
        processed += 1
    return processed


def run_watcher(audit_path: Path, ledger_path: Path, state_path: Path, once: bool) -> int:
    while True:
        process_new_events(audit_path, ledger_path, state_path)
        if once:
            return 0
        time.sleep(POLL_INTERVAL_SECONDS)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Watch C engine NDJSON audit stream and append AI verdicts to monthly CSV ledger"
        )
    )
    parser.add_argument("--audit-path", default=DEFAULT_AUDIT_PATH)
    parser.add_argument("--ledger-path", default=DEFAULT_LEDGER_PATH)
    parser.add_argument("--state-path", default=DEFAULT_STATE_PATH)
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process available lines and exit (useful for tests/cron)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    audit_path = Path(args.audit_path)
    ledger_path = Path(args.ledger_path)
    state_path = Path(args.state_path)

    return run_watcher(
        audit_path=audit_path,
        ledger_path=ledger_path,
        state_path=state_path,
        once=args.once,
    )


if __name__ == "__main__":
    raise SystemExit(main())
