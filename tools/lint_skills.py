#!/usr/bin/env python3
"""Lint SKILL.md files for portability (Agent Skills spec) and broken links. Exit 1 on errors."""
from __future__ import annotations

import re
import sys

from skillkit import CORE_END, CORE_START, ROOT, load_skills, relative_links

PORTABLE_KEYS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
MAX_DESCRIPTION = 1024
MAX_BODY_LINES = 500


def lint() -> list[str]:
    errors = []
    skills = load_skills()
    if not skills:
        return ["no skills found"]
    for s in skills:
        where = f"skills/{s.name}/SKILL.md"
        extra = set(s.fields) - PORTABLE_KEYS
        if extra:
            errors.append(f"{where}: non-portable frontmatter keys {sorted(extra)}")
        if s.fields.get("name") != s.name:
            errors.append(f"{where}: name '{s.fields.get('name')}' must equal directory name")
        if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", s.name) or len(s.name) > 64:
            errors.append(f"{where}: invalid skill name")
        if not s.description:
            errors.append(f"{where}: missing description")
        elif len(s.description) > MAX_DESCRIPTION:
            errors.append(f"{where}: description is {len(s.description)} chars (max {MAX_DESCRIPTION})")
        if len(s.body.splitlines()) > MAX_BODY_LINES:
            errors.append(f"{where}: body exceeds {MAX_BODY_LINES} lines")
        for md in [s.dir / "SKILL.md", *s.dir.rglob("references/**/*.md")]:
            text = md.read_text(encoding="utf-8")
            for link in relative_links(text):
                target = (md.parent / link.split("#", 1)[0]).resolve()
                if not target.exists():
                    errors.append(f"{md.relative_to(ROOT)}: broken link -> {link}")
    core = next((s for s in skills if s.name == "secure-coding"), None)
    if core is None or CORE_START not in core.body or CORE_END not in core.body:
        errors.append("skills/secure-coding/SKILL.md: missing core-card markers")
    return errors


if __name__ == "__main__":
    errs = lint()
    for e in errs:
        print(f"ERROR {e}")
    print(f"lint_skills: {len(errs)} error(s)")
    sys.exit(1 if errs else 0)
