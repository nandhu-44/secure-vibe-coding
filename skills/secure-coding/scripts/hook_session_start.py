#!/usr/bin/env python3
"""Claude Code SessionStart hook: put the Secure Vibe Coding core card in context for every session.

Skills load only when the model decides to invoke them, and smaller models often don't.
This hook makes the core rules always-on (like AGENTS.md), while the full skills stay
available for progressive disclosure. Disable with SECUREVIBE_SESSION_CONTEXT=off.
"""
import json
import os
import sys
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1] / "SKILL.md"
START, END = "<!-- core-card:start -->", "<!-- core-card:end -->"

PREAMBLE = """Secure Vibe Coding secure-coding rules are active for this session. Apply them to every code change. Build the
requested feature with these rules; do not stall or refuse. Before coding, ask: who can call this, which input is
untrusted, what asset is at stake, how could it be abused, and what limits (size/rate/count) apply. After writing code,
re-check your diff once against the rules, fix violations, and tell the user in 1-3 lines which protections you added
and which env vars/secrets they must set. For deeper guidance, invoke the matching skill: secure-vibe-coding:secure-web (routes,
APIs, auth, payments, uploads), secure-vibe-coding:secure-lowlevel (C/C++/Rust unsafe), secure-vibe-coding:secure-supply-chain-infra
(deps, Docker, CI, IaC), secure-vibe-coding:secure-ai-features (LLM/agents/MCP), secure-vibe-coding:secure-review (audits).
"""


def main() -> int:
    if os.environ.get("SECUREVIBE_SESSION_CONTEXT", "").lower() in {"off", "0", "false"}:
        return 0
    text = SKILL.read_text(encoding="utf-8")
    card = text[text.index(START) + len(START):text.index(END)].strip()
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart",
                                             "additionalContext": PREAMBLE + "\n" + card}}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # never break session startup
        print(f"secure-vibe-coding session hook error (ignored): {exc}", file=sys.stderr)
        sys.exit(0)
