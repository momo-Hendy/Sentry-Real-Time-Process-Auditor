# Sentry AI Bridge API Spec (v1)

This document defines the JSON contract between the C service and the Python AI analyst.
The exchange uses JSON via stdin/stdout.

## Request (C -> Python)
Python reads a single JSON object from stdin:

```json
{
  "pid": 1234,
  "name": "unknown.exe",
  "path": "C:\\Users\\...\\unknown.exe",
  "cmdline": "--silent",
  "ppid": 999,
  "timestamp": "2026-02-18T20:15:00-05:00"
}

## Response (Python -> C)
Python prints a single JSON object to stdout

```json
{
  "risk": "medium",
  "summary": "This process resembles an installer/updater. If you did not start it, it may be unwanted software.",
  "reasons": ["Unusual path", "Unknown publisher"]
}


If Python were to fail, it should still return JSON object with error summary (exceptions, etc.)


---

# AI folder (core work)

## `ai/prompt_templates.py`

```python
SYSTEM_PROMPT = """You are a security assistant for a process-auditing tool.
You explain what a process likely is and whether it seems risky.
Be cautious and avoid claiming certainty without evidence.
"""

USER_PROMPT_TEMPLATE = """Analyze this process metadata and respond with:
- risk: one of low/medium/high/unknown
- summary: 1-2 sentences, simple and user-facing
- reasons: 2-4 short bullet reasons

Process:
name: {name}
path: {path}
cmdline: {cmdline}
pid: {pid}
ppid: {ppid}
timestamp: {timestamp}
"""
