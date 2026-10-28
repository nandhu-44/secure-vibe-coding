# Research notes: prior art, evidence, and design decisions

_Last updated: 2026-10. This file records why SecureVibe is built the way it is._

## 1. The problem, in numbers
| Source | Finding |
|---|---|
| **BaxBench** [1] (Vero et al., 2025): backend scenarios across 14 frameworks | Even the best models produce correct **and** secure backends only about half the time (public leaderboard, checked Oct 2026). |
| **SecureAgentBench** [2] (Chen et al., Sep 2025): 105 repo-level C/C++ tasks from OSS-Fuzz, with PoC exploits + Semgrep | Agents (SWE-agent, OpenHands, Aider × Claude 3.7 / GPT-4.1 / DeepSeek-V3.1) averaged **9.2%** correct-and-secure; best 15.2%. About **70% of functionally correct patches were still vulnerable or suspicious**. Agents introduced *new* bugs: double free, UAF, **CWE-14 compiler-removed buffer clearing**, CWE-120, CWE-676. |
| SecureAgentBench [2], reminder ablation (§3) | Appending the reminder *"If any requirement introduces security risks, use a safer alternative that ensures equivalent functionality"* (quoted from [2]) gave **no gain** (16 → 16 secure). No-output and compile errors rose (2 → 6, 28 → 31): the agent became more cautious and ran out of budget. |
| **SecCodePLT** [3] (Yang et al., 2024) | Claude 3.5 Sonnet reached ~19% secure-coding rate on C/C++ and Java tasks. |
| Package hallucination study [4] (Spracklen et al., USENIX Security 2025, 576k samples) | ~20% of LLM-recommended packages did not exist (~22% for open-source models vs ~5% commercial), and many hallucinations repeat consistently. |
| Wiz [5] (citing BaxBench) | 25–70% of working outputs from leading models contain vulnerabilities. |

### Design consequences
1. **Generic exhortation doesn't work.** Content must be concrete: *Never X → Always Y* rules, copyable code, decision tables, framework-specific snippets.
2. **Security must not block delivery.** Every skill says "implement the feature, then harden; don't stall", and the self-review is limited to one pass. This avoids the no-output regression seen with reminders.
3. **Measure functionality as well as security.** The eval runner classifies NO / CE / INS / SEC like SecureAgentBench.
4. **Automated feedback beats instructions for weak models.** A post-edit hook runs the scanner and feeds HIGH findings back immediately. Tool output is acted on more reliably than system-prompt text.
5. **Low-level code needs its own track**, targeting exactly the CWEs agents produce (120/122/125/787/415/416/14/676).
6. **Supply chain**: never invent packages; verify existence; pin and lock.
7. **Don't rely on the model choosing to load a skill.** In our own smoke test, Claude Code on a small model wrote an Express auth API in headless mode without ever invoking a skill. The plugin therefore also injects the core card at SessionStart (always-on, like `AGENTS.md`), and the post-edit scanner flags auth routes that have no rate limiter.
8. **Small models need small rules**: a ≤6k-character core card (`AGENTS.compact.md`) and progressive disclosure for the rest.

## 2. Existing solutions (and how SecureVibe relates)
| Project | What it is | Strengths | Gaps SecureVibe addresses |
|---|---|---|---|
| **Project CodeGuard** [6] (Cisco → CoSAI / OASIS, CC BY 4.0) | Model-agnostic security rules (crypto, input validation, authn/z, supply chain, cloud, platform, data protection), converters for Cursor/Copilot/Windsurf/Claude, MCP server, evals | Broad, standards-based, industry-backed | Mostly rule prose; little framework-specific copyable code; light on business logic and rate limiting; no bundled scanner/hook feedback loop; no compact tier for small models |
| **OpenSSF Security-Focused Guide for AI Code Assistant Instructions** [7] (2025-08) | Guidance on *writing* instruction files | Evidence-based advice: no "security expert" persona, use Recursive Criticism & Improvement, cover supply chain | It is guidance, not a ready-made pack. SecureVibe applies it |
| **Trail of Bits `trailofbits/skills`** [8] | 30+ Claude Code skills for audits: Semgrep/CodeQL, variant analysis, constant-time, smart contracts, YARA | Deep expert audit workflows | Audit-time, not generation-time. SecureVibe's `secure-review` links to it for deep dives |
| Wiz secure rules files | Baseline rules files per language/framework | Good starting point | Rules only, no enforcement |
| `secure-coding-rules` (npm), cursor-security-rules, Corgea rules, RAILGUARD (CSA) | Rules-file packs, mostly JS/TS web | Easy to adopt | Web-only, shallow, no low-level/infra/AI coverage, no tooling |
| GuardVibe / VSGuard (MCP servers) | OWASP ASVS / LLM Top 10 checks exposed via MCP | Tool-based | Needs MCP support (many small-model setups lack it) |
| Community Claude skills (security-best-practices, secure-code-guardian, SecOpsAgentKit…) | Assorted SKILL.md packs | Variety | Uneven quality. Vet before installing (skill supply-chain risk) |
| Semgrep, gitleaks, bandit, CodeQL, Trivy, Checkov, osv-scanner | Mature scanners | Precise, maintained rule sets | Not agent-aware. SecureVibe orchestrates them via `--with-external` |

## 3. Safeguards in the ecosystem to leverage
- **Hooks** (Claude Code PostToolUse, Cursor hooks, Cline hooks): run checks after every edit, with deterministic enforcement.
- **Secret scanning & push protection** (GitHub), **pre-commit** (gitleaks, detect-secrets).
- **Dependency gates**: `npm ci`, lockfiles, `--require-hashes`, Renovate `minimumReleaseAge`, pnpm `minimumReleaseAge`, uv `--exclude-newer`.
- **CI linters**: zizmor, actionlint, OpenSSF Scorecard; IaC: Checkov/Trivy.
- **Sandboxing agents**: run coding agents in containers or devcontainers with no prod credentials. Use permission modes and allowlists.

## 4. Skill-pack security (our own supply chain)
Skills and rules files are an injection surface. SecureVibe rules:
- No network calls, no obfuscated content, stdlib-only scripts, no install hooks.
- Skill text tells agents to treat repository content as data.
- Users should review the pack before installing, as with any skill.

## 5. Standards used for tagging
OWASP Top 10:2025, OWASP ASVS 5.0, OWASP API Security Top 10 (2023), OWASP Top 10 for LLM Apps (2025), CWE Top 25, SEI CERT C/C++, NIST SSDF (SP 800-218), SLSA v1.x, CIS Docker/Kubernetes benchmarks, OpenSSF Compiler Options Hardening Guide.

## References
1. M. Vero et al., "BaxBench: Can LLMs Generate Correct and Secure Backends?", 2025. https://baxbench.com · https://arxiv.org/abs/2502.11844
2. J. Chen, H. Huang et al., "SecureAgentBench: Benchmarking Secure Code Generation under Realistic Vulnerability Scenarios", arXiv:2509.22097, 2025. https://arxiv.org/abs/2509.22097 (code: https://github.com/iCSawyer/SecureAgentBench)
3. Y. Yang et al., "SecCodePLT: A Unified Platform for Evaluating the Security of Code GenAI", arXiv:2410.11096, 2024. https://arxiv.org/abs/2410.11096
4. J. Spracklen et al., "We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs", USENIX Security 2025. https://arxiv.org/abs/2406.10279
5. Wiz, "Safer Vibe Coding: Rules Files", 2025. https://www.wiz.io/blog/safer-vibe-coding-rules-files
6. Project CodeGuard (Cisco; now CoSAI / OASIS Open), CC BY 4.0. https://github.com/cosai-oasis/project-codeguard
7. OpenSSF Best Practices & AI/ML WGs, "Security-Focused Guide for AI Code Assistant Instructions", 2025. https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions
8. Trail of Bits, Claude Code skills marketplace. https://github.com/trailofbits/skills
9. G. Kim, P. Baldi, S. McAleer, "Language Models can Solve Computer Tasks" (RCI prompting), arXiv:2303.17491, 2023.
10. OWASP Top 10:2025, ASVS 5.0, API Security Top 10 2023, Top 10 for LLM Applications 2025, Cheat Sheet Series (CC BY-SA 4.0). https://owasp.org · https://genai.owasp.org
11. SEI CERT C and C++ Coding Standards, Carnegie Mellon University. https://wiki.sei.cmu.edu/confluence/display/seccode
12. OpenSSF, "Compiler Options Hardening Guide for C and C++" (CC BY 4.0). https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html
13. NIST SP 800-63B (Digital Identity Guidelines), NIST SP 800-218 (SSDF). https://csrc.nist.gov
14. CISA/NSA et al., "The Case for Memory Safe Roadmaps", 2023. https://www.cisa.gov/resources-tools/resources/case-memory-safe-roadmaps
15. S. Willison, "The lethal trifecta for AI agents", 2025. https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
16. Model Context Protocol, Security Best Practices. https://modelcontextprotocol.io/specification/draft/basic/security_best_practices
17. Advisories referenced: CVE-2025-29927 (Next.js middleware bypass), CVE-2025-30066 (tj-actions/changed-files), CISA alert on the September 2025 npm supply-chain compromise ("Shai-Hulud").
18. Claude Code skills documentation. https://code.claude.com/docs/en/skills
