# Contributing

## Ground rules for skill content
- **Concrete over generic.** Every rule names the unsafe pattern and the safe replacement (code if possible). "Be careful with X" is not a rule.
- **Tag** rules with CWE and the OWASP category.
- **Don't block delivery.** Guidance must help the agent finish the feature securely, not refuse or stall.
- Keep each `SKILL.md` under 500 lines. Put depth in `references/`, linked from the SKILL.md.
- Only portable frontmatter keys: `name`, `description`, `license`, `compatibility`, `metadata`, `allowed-tools`.
- No network calls, no obfuscated text, no instructions aimed at anything other than writing secure code.

## Scanner rules
Rules live in `skills/secure-coding/scripts/rules/*.json`:
```json
{"id": "SV-XXX-000", "title": "...", "severity": "high|medium|low", "cwe": "CWE-...", "owasp": "A0x:2025",
 "langs": ["py", "js", "code", "config", "*", ...], "patterns": ["python regex", ...],
 "unless": "optional regex that suppresses a match on the same line",
 "min_entropy": 3.0, "comments": false, "fix": "one-line fix"}
```
For every new rule, add a vulnerable line to `tests/fixtures/vulnerable/` with a trailing `expect: SV-XXX-000` comment, and make sure the `tests/fixtures/safe/` files stay clean. Check noise on real code before submitting (for example, scan a large open-source repo and look at the hit count).

## Workflow
```bash
python3 -m pytest tests -q          # scanner, hook, lint, dist freshness, eval runner
python3 tools/lint_skills.py        # frontmatter + links
python3 tools/build_dist.py         # regenerate dist/ after editing any SKILL.md
```

## Evals
Add scenarios to `evals/scenarios/` (one JSON file each). Prompts must read like a normal user request and must **not** mention security. See `evals/README.md`.
