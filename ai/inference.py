from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError

from ai.prompt_templates import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE
from ai.utils import getenv, safe_str


class ProcessRequest(BaseModel):
    pid: int
    name: str
    path: Optional[str] = None
    cmdline: Optional[str] = None
    ppid: Optional[int] = None
    timestamp: Optional[str] = None


class AIResponse(BaseModel):
    risk: str = Field(default="unknown")  # low|medium|high|unknown
    summary: str = Field(default="AI analysis unavailable. Please verify this process manually.")
    reasons: List[str] = Field(default_factory=list)


def _read_stdin_json() -> Dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        raise ValueError("Empty stdin")
    return json.loads(raw)


def _mock_analyze(req: ProcessRequest) -> AIResponse:
    # Placeholder logic so integration can proceed even before real LLM wiring.
    summary = (
        f"Process '{req.name}' was detected. If you did not start it, review its location and publisher."
    )
    return AIResponse(
        risk="unknown",
        summary=summary[:240],
        reasons=["mock analyzer in use", "LLM not configured"]
    )


def _openai_analyze(req: ProcessRequest) -> AIResponse:
    # Uses the OpenAI Python SDK (v1+)
    from openai import OpenAI  # imported here so tests can run without it

    client = OpenAI(api_key=getenv("OPENAI_API_KEY"))
    model = getenv("OPENAI_MODEL", "gpt-4o-mini")

    user_prompt = USER_PROMPT_TEMPLATE.format(
        pid=req.pid,
        name=req.name,
        path=safe_str(req.path),
        cmdline=safe_str(req.cmdline),
        ppid=req.ppid if req.ppid is not None else "",
        timestamp=safe_str(req.timestamp),
    )

    # IMPORTANT: keep output machine-parseable (JSON only)
    completion = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        response_format={"type": "json_object"},
        temperature=0.2,
    )

    content = completion.choices[0].message.content or "{}"
    data = json.loads(content)

    # Normalize/validate into our response model
    try:
        return AIResponse(**data)
    except ValidationError:
        # fallback if model output shape is off
        return AIResponse(
            risk=str(data.get("risk", "unknown")),
            summary=str(data.get("summary", "AI analysis unavailable."))[:240],
            reasons=[str(x) for x in (data.get("reasons") or [])][:6],
        )


def main() -> int:
    load_dotenv()

    try:
        incoming = _read_stdin_json()
        req = ProcessRequest(**incoming)
    except Exception as e:
        out = AIResponse(risk="unknown", summary="AI analysis unavailable. Invalid input.", reasons=[f"{type(e).__name__}: {e}"])
        print(out.model_dump_json())
        return 2

    provider = getenv("AI_PROVIDER", "openai").lower()

    try:
        if provider == "openai":
            out = _openai_analyze(req)
        else:
            out = _mock_analyze(req)
    except Exception as e:
        out = AIResponse(risk="unknown", summary="AI analysis unavailable. Please verify this process manually.", reasons=[f"{type(e).__name__}: {e}"])

    # Enforce 1–2 sentence vibe (soft clamp)
    out.summary = out.summary.strip()
    if len(out.summary) > 260:
        out.summary = out.summary[:257] + "..."

    print(out.model_dump_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())