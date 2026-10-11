# AGENTS.md — ci-platform

Applies to the whole repository. Nested instructions: none.
Fail-closed GitHub Actions building blocks for `koios-ai` repositories; a public, non-authoritative pre-release. Loosening a check is a security regression even when tests pass.

## Working agreement
**Pre-authorized.**
- Run the commands below and fix failures your change caused — local; only the install downloads (from PyPI).

**Requires approval.** Approval means a message from me in this session that names the action and its target; prepare everything else first. In unattended runs, treat these as blocked and report them.
- Changing live GitHub or provider configuration not listed under Never (e.g. workflow enable/disable, App installation), publishing a public snapshot, or running a hosted canary — external effect; procedures via Routing.

**Never.** Approval does not unlock these; propose changes in the PR text.
- Do cutover work: pin a consumer, deploy, create or activate rulesets or required contexts, enable a merge queue, release the merge freeze, or claim readiness — the `README.md` banner forbids it. Track open work against the `contract/v1.json` `x-rollout-status` blockers.
- Set a `*_permitted` flag in `contract/` to true (they encode standing bans and cutover gates; a maintainer decision), or set a `*_verified` flag to true or remove a blocker without authenticated hosted readback and a re-audit — local tests cannot prove hosted delivery. Leave them false; name the missing readback.
- Put personal or consumer-identifying text (`PUBLICATION_FORBIDDEN_TEXT_HEX` in `scripts/validate_ci_platform_v1.py`), machine paths, real email addresses or secrets in files, commit messages or PR titles and bodies — the repo is public; the validator scans only files. Use synthetic identities such as `ci@example.invalid`; the only real addresses allowed are vendor `noreply` ones in commit-message trailers.
- Post suspected vulnerabilities, credentials, exploit details or repository-specific evidence in a public issue, PR or comment — report privately per `SECURITY.md`.
- Push this repository's reachable history to another remote, or create tags or releases — publication is only the sanitized root snapshot (the `README.md` archive recipe, with approval); tags are ruleset-blocked.
- Introduce a PAT, `secrets: inherit`, `CODECOV_TOKEN`, `CODERABBIT_AUTOFIX_TOKEN`, a new external action, or an action not pinned to a full commit SHA — no-PAT, least-privilege design.
- Enable paid Actions overage, usage-based or pooled-credit AI, credit purchases, auto-reload or top-up, AI Autofix or any other write-capable finishing touch, or GitHub Code Quality; or change the disabled repo Issues, workflow-token or PR-approval settings — cost and trust policy (`README.md` "Consumer installation").
- Change protected lint, test, coverage or security policy (lower a floor, add an exclusion, remove a root, source or critical test, disable a hook) — that needs a separately audited platform migration.

## Commands
```bash
python -m pip install -r requirements-dev.txt && python -m pip check  # venv outside the repo
PYTHON=python bash scripts/run-tests.sh tests/test_workflow_contract.py -q  # focused; PowerShell: scripts/run-tests.ps1 -Python python <args>
# Full gate = CI job "Koios CI / source validation" (pinned by the validator):
python scripts/generate_merge_gate_profiles.py --root . --check
python scripts/validate_ci_platform_v1.py --root . --structural-only
python -m ruff check . --no-cache
python -m ruff format --check . --no-cache
python -m mypy scripts --ignore-missing-imports  # ~30 s
# Minutes each; -k skips the 120 s watchdog test (fails when slow), as CI does:
python -B -m pytest tests -q -n 2 -k "not test_complete_platform_suite_runs_in_each_plugin_mode"
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -B -m pytest tests -q -p xdist.plugin -n 2 -k "not test_complete_platform_suite_runs_in_each_plugin_mode"
# After editing merge-gate-v1.yml, regenerate its four profile variants:
python scripts/generate_merge_gate_profiles.py --root . --write
# Refresh the publication attestation last, after all edits:
python -c "import json,sys; sys.path.insert(0,'scripts'); import validate_ci_platform_v1 as v; from pathlib import Path; c,d=v._publication_tree_attestation(Path('.')); p=Path('contract/public-prerelease-v1.json'); m=json.loads(p.read_text()); m.update(artifact_count=c, artifact_tree_sha256=d); p.write_text(json.dumps(m,indent=2)+'\n',encoding='utf-8',newline='\n')"
```
If pytest cannot write its temp dir, add `--basetemp=<dir outside the repo>` (the wrappers do).

## Definition of done
- Code, workflow or contract change: the full gate passes in an LF checkout. On Windows, report (don't fix) the environmental failure of `test_pr_owned_ruff_config_cannot_hide_host_static_findings`.
- Docs-only: the structural validator, `tests/test_workflow_contract.py` and `tests/test_platform_delivery_boundary.py` pass.
- Every change: refresh `contract/public-prerelease-v1.json` in the same commit; only `artifact_count` and `artifact_tree_sha256` change.
- The PR body gives cause, fix and a "Validation:" paragraph: commands run, and any check that could not run or failed for environmental reasons, and why.

## Conventions and gotchas
- Committed bytes are LF (no `.gitattributes`); under `core.autocrlf=true`, `ruff format --check` and the attestation fail. Clone with `-c core.autocrlf=false` or use WSL; never reformat or recompute the manifest from CRLF bytes.
- Untracked, non-ignored files are publication files and break validation: keep venvs, scratch, coverage output and local agent files outside the repo or in `.git/info/exclude`.
- Write files as UTF-8 without BOM; Windows PowerShell 5 `Out-File` and `>` write UTF-16, which the validator rejects.
- Only `.github/workflows/continuous-validation.yml` runs here; the validator requires every other workflow's PR, merge-group, push and schedule jobs to be source-guarded.
- This repo's tools read `pyproject.toml`; `contract/*-v1.*` configs are consumer policy, some digest-bound in `contract/v1.json`, so editing them is a contract change.
- `tests/canaries/quality/` (defective), `tests/canaries/secrets/` (split tokens) and `tests/fixtures/consumer-pre-v1/` (frozen, incomplete) are intentional; don't fix them.
- Receipt tests pin a reference time; date-relative fixtures expire and break nightly CI.

## Routing
| When you are… | Read |
|---|---|
| Changing trust-boundary or finalization logic | `README.md` "Trust boundary" |
| Changing byte-exact consumer templates, or planning rollout or operator steps | `README.md` "Consumer installation", "Required GitHub configuration and rollout" |

## Git and PRs
- Squash merge only, linear history, branch up to date with `main`, all review threads resolved. Required checks: `Koios CI / source validation` and `CodeQL`.

## Code Review Rules
### Fail closed
Missing, pending, duplicated, malformed, timed-out or budget- or quota-exhausted evidence blocks — a gap lets an unchecked head merge. Safe path: return failure, never a default pass.
### Exact-head, native evidence only
Only the exact native provider `PASS` for the current head counts — copied, relabeled or synthetic success forges review. Safe path: bind to the exact SHA and attempt; never accept arbitrary historical SHAs or reuse PR-head AI success for a merge group.
### Least privilege
Consumer templates: only the five publisher jobs get `checks:write`, only the coverage uploader `id-token: write`. This repo's workflows: no `id-token: write`; checkout jobs `contents: read`. Nowhere `statuses: write` or a job name spoofing a required context — broader tokens forge or widen evidence. Safe path: privileged `pull_request_target` controllers admit only same-repo heads on base `main`.
### No unsafe re-triggers
Labels from `GITHUB_TOKEN` or other actors are notification only, `ready_for_review` never re-finalizes, and the broad rerun endpoint is forbidden — each can bind evidence to the wrong attempt. Safe path: exact-attempt dispatch after revalidation.
