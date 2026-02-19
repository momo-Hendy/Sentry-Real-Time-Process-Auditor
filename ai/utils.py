from __future__ import annotations

import os
from typing import Optional


def is_probably_system_binary(path: Optional[str]) -> bool:
    """Heuristic only: helps reduce noise in your prompt and output."""
    if not path:
        return False
    p = path.lower()

    # Windows-ish paths
    if "\\windows\\system32\\" in p or "\\windows\\syswow64\\" in p:
        return True

    # Linux-ish paths
    if p.startswith("/usr/bin/") or p.startswith("/bin/") or p.startswith("/usr/sbin/"):
        return True

    return False


def safe_str(x: object, default: str = "") -> str:
    return default if x is None else str(x)


def getenv(key: str, default: str = "") -> str:
    return os.getenv(key, default).strip()