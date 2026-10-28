"""Shared helpers for reading SKILL.md files (stdlib only)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "skills"
SKILL_ORDER = ["secure-coding", "secure-web", "secure-lowlevel", "secure-supply-chain-infra", "secure-ai-features", "secure-review"]
CORE_START, CORE_END = "<!-- core-card:start -->", "<!-- core-card:end -->"


@dataclass
class Skill:
    name: str
    dir: Path
    frontmatter_raw: str
    fields: dict
    body: str

    @property
    def description(self) -> str:
        return self.fields.get("description", "")


def parse_frontmatter(text: str) -> tuple[str, dict, str]:
    if not text.startswith("---\n"):
        raise ValueError("SKILL.md must start with '---' frontmatter")
    end = text.index("\n---\n", 4)
    raw = text[4:end]
    body = text[end + 5:]
    fields: dict = {}
    current = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        m = re.match(r"^([A-Za-z][\w-]*):\s*(.*)$", line)
        if m:
            current = m.group(1)
            val = m.group(2).strip()
            fields[current] = val.strip("\"'") if val else {}
        elif current and isinstance(fields.get(current), dict):
            sm = re.match(r"^\s+([\w-]+):\s*(.*)$", line)
            if sm:
                fields[current][sm.group(1)] = sm.group(2).strip().strip("\"'")
    return raw, fields, body


def load_skills() -> list[Skill]:
    skills = []
    names = [n for n in SKILL_ORDER if (SKILLS_DIR / n / "SKILL.md").exists()]
    names += sorted(p.parent.name for p in SKILLS_DIR.glob("*/SKILL.md") if p.parent.name not in names)
    for n in names:
        text = (SKILLS_DIR / n / "SKILL.md").read_text(encoding="utf-8")
        raw, fields, body = parse_frontmatter(text)
        skills.append(Skill(n, SKILLS_DIR / n, raw, fields, body))
    return skills


def core_card(core: Skill) -> str:
    b = core.body
    return b[b.index(CORE_START) + len(CORE_START):b.index(CORE_END)].strip()


LINK_RE = re.compile(r"\]\((?!https?://|#|mailto:)([^)\s]+)\)")


def relative_links(body: str) -> list[str]:
    return LINK_RE.findall(body)


def rewrite_links(body: str, skill_dir: Path, base: str) -> str:
    """Point relative links at `base` + repo-relative path (for rule files copied into other projects)."""
    def repl(m):
        target = (skill_dir / m.group(1)).resolve()
        try:
            rel = target.relative_to(ROOT).as_posix()
        except ValueError:
            return m.group(0)
        return f"]({base}{rel})"
    body = body.replace("${CLAUDE_SKILL_DIR}/../", base + "skills/")
    body = body.replace("${CLAUDE_SKILL_DIR}/", base + skill_dir.relative_to(ROOT).as_posix() + "/")
    return LINK_RE.sub(repl, body)
