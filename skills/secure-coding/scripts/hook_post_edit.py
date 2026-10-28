#!/usr/bin/env python3
"""Claude Code PostToolUse hook: scan the file the agent just wrote or edited.

- HIGH findings: exit 2 with findings on stderr, so Claude sees them and fixes the code immediately.
- MEDIUM findings: exit 0 with JSON `additionalContext`, a non-blocking hint to the model.
- Otherwise it is silent. Never crashes the session: any internal error exits 0.

Env:
  SECUREVIBE_HOOK=off            disable the hook
  SECUREVIBE_HOOK_BLOCK=medium   also block on medium findings
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def main() -> int:
    if os.environ.get("SECUREVIBE_HOOK", "").lower() in {"off", "0", "false"}:
        return 0
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0
    tool_input = payload.get("tool_input") or {}
    path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not path or not os.path.isfile(path):
        return 0

    import secscan

    findings = secscan.scan_paths([path], secscan.load_rules(secscan.RULES_DIR))
    block_level = secscan.SEVERITIES.get(os.environ.get("SECUREVIBE_HOOK_BLOCK", "high"), 3)
    blocking = [f for f in findings if secscan.SEVERITIES[f.severity] >= block_level]
    advisory = [f for f in findings if f.severity == "medium" and f not in blocking]

    if blocking:
        print("SecureVibe found security issues in the file you just wrote. Fix them now "
              "(or, if a finding is a verified false positive, add `securevibe: ignore[RULE-ID] reason` on that line):\n"
              + secscan.render_text(blocking, color=False), file=sys.stderr)
        return 2
    if advisory:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "SecureVibe advisory (review, fix if real):\n" + secscan.render_text(advisory, color=False),
        }}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # a broken hook must never break the agent loop
        print(f"securevibe hook error (ignored): {exc}", file=sys.stderr)
        sys.exit(0)
