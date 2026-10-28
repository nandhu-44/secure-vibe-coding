"""Scanner tests: every `expect:` annotation in vulnerable fixtures must be reported; safe fixtures must be clean."""
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "secure-coding" / "scripts"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(SCRIPTS))
import secscan  # noqa: E402

RULES = secscan.load_rules(secscan.RULES_DIR)
EXPECT_RE = re.compile(r"expect(-above)?:\s*([A-Z0-9, -]+)")


def expectations(path: Path):
    exp = set()
    for i, line in enumerate(path.read_text().splitlines(), start=1):
        m = EXPECT_RE.search(line)
        if m:
            target = i - 1 if m.group(1) else i
            for rid in m.group(2).split(","):
                exp.add((target, rid.strip()))
    return exp


VULN_FILES = sorted(p for p in FIXTURES.joinpath("vulnerable").rglob("*") if p.is_file())


@pytest.mark.parametrize("path", VULN_FILES, ids=lambda p: p.name)
def test_vulnerable_fixture_flags_expected(path):
    found = {(f.line, f.rule_id) for f in secscan.scan_paths([str(path)], RULES)}
    missing = expectations(path) - found
    assert not missing, f"missing findings (line, rule): {sorted(missing)}"


@pytest.mark.parametrize("path", VULN_FILES, ids=lambda p: p.name)
def test_vulnerable_fixture_has_no_unexpected_findings(path):
    expected = expectations(path)
    found = {(f.line, f.rule_id) for f in secscan.scan_paths([str(path)], RULES)}
    extra = found - expected
    assert not extra, f"unexpected findings (line, rule): {sorted(extra)}"


def test_safe_fixtures_are_clean():
    findings = secscan.scan_paths([str(FIXTURES / "safe")], RULES)
    assert not findings, "\n" + secscan.render_text(findings, color=False)


# Secrets are assembled at runtime so the repository never contains real-looking credentials.
SECRET_SAMPLES = {
    "SV-SEC-001": "aws_key = '" + "AKIA" + "Z7QW3RTY5UIO2PLK" + "'",
    "SV-SEC-002": "token = '" + "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8" + "'",
    "SV-SEC-004": "STRIPE = '" + "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc9Xk" + "'",
    "SV-SEC-005": "client = OpenAI(api_key='" + "sk-" + "proj-" + "Qm9vYmFyQmF6UXV4Q29yZ2VHcmF1bHRHYXJwbHk" + "')",
    "SV-SEC-007": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "SV-SEC-008": "DATABASE_URL = 'postgres://admin:" + "Tr0ub4dor3x" + "@db.prod.internal.net:5432/app'",
    "SV-SEC-009": "password = '" + "Hunter2!xQ9" + "'",
    "SV-SEC-010": "const k = process.env.NEXT_PUBLIC_" + "OPENAI_API_KEY;",
}

SECRET_NEGATIVES = [
    "password = os.environ['DB_PASSWORD']",
    "api_key = '${API_KEY}'",
    "password = 'changeme'",
    "DATABASE_URL = 'postgres://user:password@localhost:5432/app'",
    "secret = 'your-secret-here'",
    "const k = process.env.NEXT_PUBLIC_" + "STRIPE_PUBLISHABLE_KEY;",
    "aws_key = 'AKIAIOSFODNN7EXAMPLE'",
]


@pytest.mark.parametrize("rule_id,line", list(SECRET_SAMPLES.items()))
def test_secret_detection(tmp_path, rule_id, line):
    f = tmp_path / ("sample.js" if "const" in line else "sample.py")
    f.write_text(line + "\n")
    ids = {x.rule_id for x in secscan.scan_paths([str(f)], RULES)}
    assert rule_id in ids


@pytest.mark.parametrize("line", SECRET_NEGATIVES)
def test_secret_placeholders_not_flagged(tmp_path, line):
    f = tmp_path / ("sample.js" if "const" in line else "sample.py")
    f.write_text(line + "\n")
    ids = {x.rule_id for x in secscan.scan_paths([str(f)], RULES) if x.rule_id.startswith("SV-SEC")}
    assert not ids


def test_suppression_comment(tmp_path):
    f = tmp_path / "s.py"
    f.write_text("URL = 'http://legacy-printer.office.lan/'  # securevibe: ignore[SV-NET-001] LAN device, no TLS support\n")
    assert not secscan.scan_paths([str(f)], RULES)


def test_cli_json_and_exit_code():
    res = subprocess.run([sys.executable, str(SCRIPTS / "secscan.py"), str(FIXTURES / "vulnerable" / "parse.c"), "--json"],
                         capture_output=True, text=True)
    assert res.returncode == 1
    data = json.loads(res.stdout)
    assert any(f["rule_id"] == "SV-MEM-001" for f in data["findings"])
    res = subprocess.run([sys.executable, str(SCRIPTS / "secscan.py"), str(FIXTURES / "safe")], capture_output=True, text=True)
    assert res.returncode == 0, res.stdout


def test_rule_ids_unique_and_fields_present():
    ids = [r["id"] for r in RULES]
    assert len(ids) == len(set(ids))
    for r in RULES:
        assert r["severity"] in secscan.SEVERITIES
        assert r["fix"] and r["title"] and r["patterns"]
