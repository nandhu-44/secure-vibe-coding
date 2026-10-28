"""Pack-level tests: skill lint, dist freshness, hook behaviour, size budgets for small-context agents."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import lint_skills  # noqa: E402
from skillkit import core_card, load_skills  # noqa: E402

HOOK = ROOT / "skills" / "secure-coding" / "scripts" / "hook_post_edit.py"
FIX = ROOT / "tests" / "fixtures"


def test_skills_lint_clean():
    assert lint_skills.lint() == []


def test_dist_up_to_date():
    res = subprocess.run([sys.executable, str(ROOT / "tools" / "build_dist.py"), "--check"], capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr


def test_compact_rules_fit_small_context_and_windsurf_limit():
    compact = (ROOT / "dist" / "AGENTS.compact.md").read_text()
    assert len(compact) < 6000          # Windsurf per-rule limit; ~1.5k tokens for 4-8k context models
    for p in (ROOT / "dist" / ".windsurf" / "rules").glob("*.md"):
        assert len(p.read_text()) <= 6000, p


def test_core_card_present_in_every_core_output():
    card = core_card(load_skills()[0])
    for rel in ["AGENTS.md", "AGENTS.compact.md", ".github/copilot-instructions.md", ".clinerules/securevibe.md"]:
        assert card in (ROOT / "dist" / rel).read_text(), rel


def run_hook(path):
    payload = json.dumps({"tool_name": "Write", "tool_input": {"file_path": str(path)}})
    return subprocess.run([sys.executable, str(HOOK)], input=payload, capture_output=True, text=True)


def test_hook_blocks_on_high():
    res = run_hook(FIX / "vulnerable" / "parse.c")
    assert res.returncode == 2
    assert "SV-MEM-001" in res.stderr


def test_hook_silent_on_safe_file():
    res = run_hook(FIX / "safe" / "app.py")
    assert res.returncode == 0 and res.stdout == "" and res.stderr == ""


def test_hook_advisory_on_medium(tmp_path):
    f = tmp_path / "client.js"
    f.write_text('const API = "http://api.vendor-service.com/v1";\n')
    res = run_hook(f)
    assert res.returncode == 0
    ctx = json.loads(res.stdout)["hookSpecificOutput"]["additionalContext"]
    assert "SV-NET-001" in ctx


def test_hook_tolerates_garbage_input():
    res = subprocess.run([sys.executable, str(HOOK)], input="not json", capture_output=True, text=True)
    assert res.returncode == 0


def test_plugin_manifests_valid():
    for rel in [".claude-plugin/plugin.json", ".claude-plugin/marketplace.json", "hooks/hooks.json"]:
        json.loads((ROOT / rel).read_text())


def test_eval_runner_end_to_end(tmp_path):
    out = tmp_path / "res.json"
    agent = f"{sys.executable} {ROOT / 'tests' / 'fake_agent.py'} {{prompt}}"
    res = subprocess.run([sys.executable, str(ROOT / "evals" / "run_eval.py"), "--agent", agent, "--modes", "none,agents-md,skills",
                          "--only", "py-ping-tool", "--out", str(out)], capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, res.stderr
    results = {r["mode"]: r for r in json.loads(out.read_text())}
    assert results["none"]["category"] == "INS"
    assert results["agents-md"]["category"] == "SEC"
    assert results["skills"]["category"] == "SEC"
