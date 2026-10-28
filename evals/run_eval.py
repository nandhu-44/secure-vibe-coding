#!/usr/bin/env python3
"""Measure whether SecureVibe makes a coding agent write more secure code.

For each scenario (evals/scenarios/*.json) and each mode, the runner:
  1. creates a fresh temp workdir (and installs the pack into it, for "with" modes),
  2. runs your agent CLI non-interactively with the scenario prompt,
  3. classifies the result SecureAgentBench-style:
       NO  - no code produced        CE - produced code does not parse/compile
       INS - insecure (scanner findings in must_not_find, or a check failed)
       SEC - secure (no forbidden findings, all checks pass)

Placeholders in --agent: {prompt}, {workdir}, {pack_root}. The template is split with shlex
BEFORE substitution, so the prompt is passed as one argument and never interpreted by a shell.

Examples:
  # Claude Code: baseline vs plugin
  run_eval.py --agent 'claude -p {prompt} --permission-mode acceptEdits' --modes none \
              --agent-with 'claude -p {prompt} --permission-mode acceptEdits --plugin-dir {pack_root}' --modes none,plugin
  # Aider + local Ollama model, compact rules
  run_eval.py --agent 'aider --model ollama_chat/qwen2.5-coder:7b --yes-always --no-git --no-show-model-warnings --message {prompt}' \
              --modes none,compact --compact-read
  # OpenCode / Codex read AGENTS.md from the workdir
  run_eval.py --agent 'opencode run {prompt}' --modes none,agents-md

Pack modes:
  none        no pack (baseline)
  agents-md   dist/AGENTS.md copied to AGENTS.md
  compact     dist/AGENTS.compact.md copied to AGENTS.md (small-context models)
  skills      skills/ copied to .claude/skills/ (Claude Code / Agent Skills-compatible agents)
  plugin      nothing copied; use {pack_root} in --agent-with (e.g. claude --plugin-dir {pack_root})
"""
from __future__ import annotations

import argparse
import fnmatch
import glob
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "secure-coding" / "scripts"))
import secscan  # noqa: E402

CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".c", ".h", ".cc", ".cpp", ".rs", ".java", ".rb", ".php",
            ".yml", ".yaml", ".tf", ".sql", ".json"}
CODE_NAMES = ("Dockerfile", "docker-compose")
PACK_FILES = {"AGENTS.md", "AGENTS.compact.md"}
IGNORE_DIRS = {".claude", ".git", "node_modules", ".aider.tags.cache.v4", "__pycache__", ".venv", "venv"}


def install_pack(mode: str, workdir: Path, compact_read: bool) -> list[str]:
    if mode == "agents-md":
        shutil.copy(ROOT / "dist" / "AGENTS.md", workdir / "AGENTS.md")
    elif mode == "compact":
        shutil.copy(ROOT / "dist" / "AGENTS.compact.md", workdir / "AGENTS.md")
        if compact_read:
            shutil.copy(ROOT / "dist" / "AGENTS.compact.md", workdir / "AGENTS.compact.md")
            return ["--read", "AGENTS.compact.md"]
    elif mode == "skills":
        shutil.copytree(ROOT / "skills", workdir / ".claude" / "skills")
    return []


def generated_files(workdir: Path) -> list[Path]:
    out = []
    for p in workdir.rglob("*"):
        if not p.is_file() or any(part in IGNORE_DIRS for part in p.relative_to(workdir).parts):
            continue
        if p.name in PACK_FILES or p.name.startswith(".aider"):
            continue
        if p.suffix.lower() in CODE_EXT or p.name.startswith(CODE_NAMES) or "/.github/workflows/" in p.as_posix():
            if p.name in {"package-lock.json", "tsconfig.json"}:
                continue
            out.append(p)
    return out


def syntax_ok(files: list[Path]) -> tuple[bool, str]:
    for f in files:
        cmd = None
        if f.suffix == ".py":
            cmd = [sys.executable, "-m", "py_compile", str(f)]
        elif f.suffix in {".js", ".mjs", ".cjs"} and shutil.which("node"):
            cmd = ["node", "--check", str(f)]
        elif f.suffix == ".c" and shutil.which("gcc"):
            cmd = ["gcc", "-fsyntax-only", "-w", str(f)]
        elif f.suffix == ".json":
            try:
                json.loads(f.read_text())
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                return False, f"{f.name}: {e}"
        if cmd:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                return False, f"{f.name}: {(r.stderr or r.stdout).strip()[:300]}"
    return True, ""


def run_checks(scn: dict, workdir: Path, files: list[Path]) -> list[str]:
    failures = []
    for c in scn.get("checks", []):
        rx = re.compile(c["pattern"], re.I | re.M)
        targets = [f for f in files if fnmatch.fnmatch(f.name, c.get("glob", "*"))]
        hits = [f for f in targets if rx.search(f.read_text(errors="replace"))]
        if c["type"] == "regex_any" and not hits:
            failures.append(f"missing: {c['desc']}")
        if c["type"] == "regex_none" and hits:
            failures.append(f"violated: {c['desc']} ({', '.join(h.name for h in hits)})")
    return failures


def run_one(scn: dict, mode: str, template: str, timeout: int, compact_read: bool, keep: bool) -> dict:
    workdir = Path(tempfile.mkdtemp(prefix=f"sv-{scn['id']}-{mode}-"))
    extra = install_pack(mode, workdir, compact_read) if mode != "none" else []
    argv = [tok.replace("{prompt}", scn["prompt"]).replace("{workdir}", str(workdir)).replace("{pack_root}", str(ROOT))
            for tok in shlex.split(template)]
    if extra and argv and Path(argv[0]).name == "aider":
        argv[1:1] = extra
    t0 = time.time()
    try:
        proc = subprocess.run(argv, cwd=workdir, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        agent_rc, agent_err = proc.returncode, proc.stderr[-500:]
    except subprocess.TimeoutExpired:
        agent_rc, agent_err = -1, "timeout"
    elapsed = round(time.time() - t0, 1)

    files = generated_files(workdir)
    result = {"scenario": scn["id"], "domain": scn.get("domain"), "mode": mode, "seconds": elapsed, "agent_rc": agent_rc,
              "files": [str(f.relative_to(workdir)) for f in files], "workdir": str(workdir) if keep else None}
    if not files:
        result.update(category="NO", detail=agent_err)
    else:
        ok, err = syntax_ok(files)
        findings = secscan.scan_paths([str(f) for f in files], secscan.load_rules(secscan.RULES_DIR))
        forbidden = sorted({f"{x.rule_id}@{Path(x.file).name}:{x.line}" for x in findings if x.rule_id in scn["must_not_find"]})
        failures = run_checks(scn, workdir, files)
        result.update(findings=forbidden, check_failures=failures, all_findings=len(findings), syntax_error=err or None)
        result["category"] = "CE" if not ok else ("INS" if forbidden or failures else "SEC")
    if not keep:
        shutil.rmtree(workdir, ignore_errors=True)
    return result


def summarize(results: list[dict]) -> str:
    modes = sorted({r["mode"] for r in results}, key=lambda m: (m != "none", m))
    lines = ["| mode | n | SEC | INS | CE | NO | secure rate |", "|---|---|---|---|---|---|---|"]
    for m in modes:
        rs = [r for r in results if r["mode"] == m]
        c = {k: sum(1 for r in rs if r["category"] == k) for k in ("SEC", "INS", "CE", "NO")}
        lines.append(f"| {m} | {len(rs)} | {c['SEC']} | {c['INS']} | {c['CE']} | {c['NO']} | {c['SEC'] / max(len(rs), 1):.0%} |")
    lines.append("\n| scenario | " + " | ".join(modes) + " |")
    lines.append("|---|" + "---|" * len(modes))
    for sid in sorted({r["scenario"] for r in results}):
        cells = []
        for m in modes:
            r = next((x for x in results if x["scenario"] == sid and x["mode"] == m), None)
            cells.append(r["category"] if r else "-")
        lines.append(f"| {sid} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agent", required=True, help="agent command template for baseline (and pack modes unless --agent-with)")
    ap.add_argument("--agent-with", help="agent command template for non-baseline modes")
    ap.add_argument("--modes", default="none,agents-md", help="comma list: none, agents-md, compact, skills, plugin")
    ap.add_argument("--scenarios", default=str(ROOT / "evals" / "scenarios" / "*.json"), help="glob of scenario files")
    ap.add_argument("--only", help="comma list of scenario ids")
    ap.add_argument("--repeat", type=int, default=1, help="runs per scenario/mode (LLM output varies)")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--compact-read", action="store_true", help="for aider: pass --read AGENTS.compact.md")
    ap.add_argument("--keep", action="store_true", help="keep workdirs for inspection")
    ap.add_argument("--out", default="eval-results.json")
    args = ap.parse_args()

    scenarios = [json.loads(Path(p).read_text()) for p in sorted(glob.glob(args.scenarios))]
    if args.only:
        wanted = set(args.only.split(","))
        scenarios = [s for s in scenarios if s["id"] in wanted]
    if not scenarios:
        print("no scenarios matched", file=sys.stderr)
        return 2

    results = []
    for scn in scenarios:
        for mode in args.modes.split(","):
            template = args.agent_with if (mode != "none" and args.agent_with) else args.agent
            for i in range(args.repeat):
                r = run_one(scn, mode, template, args.timeout, args.compact_read, args.keep)
                r["run"] = i
                results.append(r)
                print(f"{scn['id']:<22} {mode:<10} #{i} {r['category']:<3} {r['seconds']:>6}s "
                      f"{' '.join(r.get('findings', []))} {' | '.join(r.get('check_failures', []))}", flush=True)
    Path(args.out).write_text(json.dumps(results, indent=2))
    print("\n" + summarize(results))
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
