# Koios CI Platform

Centrally owned GitHub Actions building blocks for `koios-ai`. A sanitized
public pre-release is authorized solely for non-authoritative hosted canaries.
The platform separates an organization ruleset workflow from label-driven
consumer controllers because GitHub ruleset workflows cannot implement the
final-review cadence by themselves.

> **NOT READY — CUTOVER IS FORBIDDEN.** Publication is permitted only as the
> sanitized root snapshot attested by `contract/public-prerelease-v1.json`.
> Publication does not authorize a consumer pin, required context, ruleset,
> merge, deployment, or release of the merge freeze. All hosted canary results
> remain non-authoritative. In addition to hosted
> canaries, `contract/v1.json` records the unresolved architectural blockers:
> same-head zero-job attempt enforcement, fresh-job isolation after
> PR-controlled execution, closed Dependabot admission, and protected-main /
> scheduled heavy validation, plus an organization-level same-repository
> feature-branch Actions secret/token boundary.
> The final blocker is a hosted-proven, exact-head provider-native PASS
> attestation for CodeRabbit and Codex, plus a bounded supported-release
> manifest for staged fleet upgrades. The no-PAT dispatch topology is locally
> implemented but remains hosted-unverified.
> Hosted canary generation 2 exposed a least-privilege mismatch: a same-repo
> trusted-base controller received `issues: write` but GitHub rejected both PR
> label deletions with HTTP 403. The repair requests only
> `pull-requests: write`; it remains unverified until that exact workflow is on
> the protected default branch and a new labeled lifecycle canary proves both
> deletions and absence readback. This does not change release or cutover
> authority.

## Closed reusable contract

`contract/v1.json` permits only:

- profiles `baseline`, `python`, `node`, `powershell`, and `critical-ml`;
- full lowercase 40-character head and base commit SHAs;
- a SHA-256 digest of the canonical changed-file list;
- Python 3.11, 3.12, or 3.13 (default 3.12);
- evidence retention from one through seven days (default three).

There is no command input and no secret input. A consumer must pin every
platform workflow and action to one literal full commit SHA recorded in
`.github/ci-platform.lock.json`. `secrets: inherit` is forbidden.

## Source-bound merge gate v1 (blocked release)

Five immutable source workflows expose one stable terminal job/check context
named `CI / required` with no expression-based job naming. Their workflow
display names are profile-qualified so hosted suites remain distinguishable:

- `baseline` — `.github/workflows/merge-gate-v1.yml`;
- `python` — `.github/workflows/merge-gate-python-v1.yml`;
- `node` — `.github/workflows/merge-gate-node-v1.yml`;
- `powershell` — `.github/workflows/merge-gate-powershell-v1.yml`;
- `critical-ml` — `.github/workflows/merge-gate-critical-ml-v1.yml`.

The baseline file is canonical and
`scripts/generate_merge_gate_profiles.py --check` rejects drift in the other
four. Every file has only unfiltered `pull_request` and `merge_group` events,
read-only permissions, an immutable profile constant, and a literal
profile-scoped, non-cancelling concurrency key. Ruleset workflows omit
`cancel-in-progress` because cancellation is unsupported for this rule type.
Every profile job remains source-guarded when
`github.repository == 'koios-ai/ci-platform'`, while the terminal name stays
the static consumer contract `CI / required`. Conditional skipped-job names are
forbidden because GitHub can expose the unevaluated expression as the hosted
check name. After the bootstrap change lands, disable all five merge-gate
workflows in the platform source repository and capture an authenticated
readback proving each is disabled; leave `continuous-validation.yml` enabled.
Until that readback exists, source-side duplicate suites remain a release
blocker and the workflows must not be used as consumer authority.
The source repository instead has one distinct `continuous-validation.yml`
gate for pull requests, merge groups, `main`, and schedules. After a pinned
Python 3.12.13 install and `pip check`, it enforces generator drift, structural
contract validation, Ruff lint/format, repository-wide script mypy, and the
ordinary pytest suite in both plugin modes.
Both the source workflow and the local dual-plugin watchdog use exactly two
pinned xdist workers; isolated mode loads only `xdist.plugin` explicitly, and
the local complete-suite subprocess deadline remains fixed at 120 seconds.
Its repository-and-event concurrency cancels only superseded pull-request
runs; merge-group, `main` push, and scheduled runs retain independent keys and
are never cancelled by that policy. The platform's privileged
`pull_request_target` label invalidator also admits only same-repository heads,
so an external fork cannot allocate its write-capable runner.
Those requirements are not yet hash locked, so the control-plane supply chain
remains blocked until `--require-hashes` or a digest-pinned prebuilt image is
used.

The organization must own a required, non-repository-editable, single-select
`ci_profile` property. It has no default, empty, or inherited value: a user
must explicitly assign every repository. Five non-overlapping organization
rulesets target `props.ci_profile:<profile>` on `~DEFAULT_BRANCH` and each
requires only its matching workflow path.
The property is routing authority only: workflow code never fetches or reads
custom properties. Hosted readback must prove exactly one expected workflow
and zero unexpected profile workflows before release.

`scripts/merge_gate_policy.py` validates the closed profile/path pair and
immutable `workflow_ref`, exact base/head SHA, profile-scoped multipush
cancellation, draft and merge-group behavior, provider states, and explicit
required/not-applicable lanes. Dependabot is recognized from pull-request
author identity—not event sender—and bound to the same head repository, exact
head SHA, and dependency-file-only change set. The NUL-delimited Git diff
includes deletions and both sides of renames/copies, so moving or deleting
non-dependency code cannot disappear from that scope proof.
`--find-copies-harder` also exposes an unchanged source file copied onto an
allowed dependency path. Fork pull requests are explicitly unsupported by v1
and fail before admission.

Initial, draft, and otherwise non-final runs execute bounded fast scope only:
provenance, event/head validation, and changed-file classification. Target
dependencies, tests, scans, and coverage all require a successful
`admitted=true` final-candidate result. The terminal job is always present and
fails closed when any required result is failed, skipped, missing, or
inconclusive.

The trusted fast/static lanes never install or execute target dependencies.
Every actual workflow run rejects tracked Git symlinks, gitlinks, and unmerged
entries before host-side target reads. Profile-specific target dependency,
audit, type, and test work is staged into constrained OCI containers:

- baseline parses repository JSON, TOML, and YAML;
- Python runs pinned Ruff 0.14.14 and formatting on the trusted static lane.
  A networked container sees only a closed exact-pin requirements graph;
  networkless containers then run strict mypy 1.19.1 and the protected-base
  pytest policy against separately installed dependencies;
- critical-ML additionally requires protected leakage, lineage, model, parity,
  and schema hooks;
- Node requires one lockfile, an exact `packageManager`, a protected-base
  explicit per-file test manifest, and the digest-pinned Node 22.14.0 image.
  The active npm path verifies its image-owned npm 10.9.2 before network use,
  audits production and development dependencies at the lowest blocking
  severity, and rejects non-registry manifest, override, and lockfile sources.
  pnpm and Yarn remain blocked until their Corepack artifacts are digest-bound;
- PowerShell remains blocked before any PSGallery access until the Pester 5.7.1
  artifact is digest-bound.

These target-runtime results are diagnostic, not admission authority. Candidate
code can still forge the scratch evidence it owns, and the bind-mounted output
directory has no pre-execution storage quota. Every generated workflow
therefore contains an unconditional fail-closed supervisor-canary stop.
Release requires a trusted target supervisor that observes execution itself,
reconstructs authoritative evidence, and uses bounded tmpfs plus controlled
extraction.

Security always includes the platform-owned `secret_scan.py` floor. Its
tool/canonical-config digest and positive/negative canaries are contract-bound, it reads
only Git-tracked target files, redacts values, and fails closed on oversized
files. Python/critical add target-manifest `pip-audit` and Bandit; Node adds its
manager audit. Baseline and PowerShell may mark the profile-specific security
extension not applicable, but never skip the common scan. Coverage is
explicitly not applicable for baseline, Node, and PowerShell rather than being
represented as a synthetic PASS.

`.github/workflows/required.yml` and `reusable-final.yml` are explicitly named
legacy/inactive; the former is manual-dispatch-only and its terminal job is
named `LEGACY / inactive fast diagnostics`, so it cannot publish the stable
`CI / required` context. Therefore
the five mapped profile workflows are the complete source-bound
`pull_request` plus `merge_group` candidate set for v1.
Legacy workflows must still parse before hosted evidence can run: `job.*` and
`runner.*` contexts are forbidden in job-level environment maps. Immutable
workflow provenance is bound in step-level environment maps, while runner temp
paths are exported by the first shell step through `GITHUB_ENV`. The
PowerShell test wrapper derives every owned artifact path with `Join-Path`, so
cleanup remains contained on Windows and Linux runners.

The 2026-07-27 organization readback shows GitHub Code Quality disabled (the UI
offers `Enable Code Quality`), with no context, threshold, configuration, or
canary. It is permanently excluded from this architecture. Release remains
blocked until authenticated receipts prove organization repository access is
`No repositories` with enforcement and that Code Quality billing has ceased.
Both receipts must be present together and bind the exact organization/surface,
fresh capture time, authenticated method, identified reviewer, GitHub provider,
semantic state, and canonical SHA-256 digest. Null, partial, stale, malformed,
or contradictory receipts preserve both release blockers. The separate AI
findings page may be disabled, but the product's in-PR AI fixes are not a
documented optional mode; this is why no deterministic-only Code Quality canary
exists.
The deterministic replacement map in
`contract/deterministic-quality-v1.json` binds every severe historical class
to the production Ruff or strict-mypy configuration, its exact diagnostic ID,
and a failing canary; CodeQL and other repository-owned security checks remain
distinct.

DeepSource disposition is also blocked. JSON Schema validates both the blocked
template (including null evidence) and the stronger complete-map shape. A
complete map must then pass semantic receipt validation: source config receipts
bind repository/source SHA/config digest/analyzers; hosted inventories bind
repository, provider signal IDs, reviewer/source metadata, and fresh
timestamps; positive and negative canaries bind allowlisted owners, exact
versions/config digests, fixture digests, output digests, and execution time.
The live-ruleset and App/subscription preconditions are hashed evidence-file
receipts with authenticated DeepSource/provider, source, reviewer, freshness,
and semantic-state validation; bare booleans cannot authorize a transition.
Expected exits and diagnostic hashes come from the immutable platform schema,
not the execution receipt; actual values must match them exactly. Boolean
exits, exit 126/127, coordinated receipt mutations, and unrelated failures
therefore cannot prove a vulnerability. SCA graphs bind
manifest/profile/package sets to CycloneDX-shaped SBOMs.

The 2026-07-27 DeepSource readback records the fixed Team subscription,
fail-on-no-data enabled, checked-in `.deepsource.toml` enabled, automatic AI
credit recharge disabled, and the master AI Agents switch disabled. AI Review,
AI Autofix, enhanced-secrets AI, and PR-report-card AI must remain disabled,
but their individual hosted child-state receipts (including PR report card)
and the hard overage stop remain blockers. A `DeepSource: AI Review` context is
forbidden drift that fails closed.
Deterministic analysis and SCA remain active. For each non-AI signal, a complete
evidence set may support either `retain-unique-defense-in-depth` under the
fixed-price/unlimited-PR policy or `replace-proven-duplicate`; the validator
does not impose one estate-wide answer. Reachability, Dynamic Risk, EPSS, CVSS,
and license-compliance are never silently retired. A replacement disposition
requires an exhaustive, unique typed mapping for every hosted static rule and
each of those five SCA capabilities to one deterministic central owner and an
executed negative canary bound to the parent proof. The complete per-item
semantic record—provider item, owner/tool/version/config, command, fixture,
captured output, diagnostic digest, nonzero exit, and execution time—is covered
by the RSA-signed execution payload. Its signed key set must exactly equal the
hosted static-rule plus SCA-capability inventories, and each replacement receipt
must exactly match its signed record; recomputing ordinary file hashes is not
authorization. Missing, extra, duplicated, mismatched, or misowned entries
retain/block the provider signal instead of claiming parity.
Usage-priced AI Review has
only one permitted outcome: `disable-usage-based-ai`. Hash-valid but
semantically empty receipts are not proof.

## Required-context ownership

| Required context | Sole publisher |
| --- | --- |
| `CI / required` | the selected profile workflow's `merge` terminal job (exactly one of five immutable paths) |
| `Security / required` | `.github/workflows/final-required.yml:publish-security` |
| `Coverage / required` | `.github/workflows/final-required.yml:publish-coverage` |
| `AI / CodeRabbit final` | `.github/workflows/coderabbit-final.yml:publish-coderabbit` |
| `AI / Codex final` | `.github/workflows/codex-final-gate.yml:publish-codex` |
| `AI / findings resolved` | `.github/workflows/ai-findings-resolved.yml:publish-findings` |

Only those five consumer jobs have `checks:write`. They are metadata-only,
never check out pull-request code, never receive provider credentials, and
cannot write commit statuses. Security and coverage are published separately;
one successful gate cannot mint the other context.

`Security / required` also folds in native DeepSource evidence when the exact
protected-base commit contains `.deepsource.toml`. The immutable platform
publisher polls commit statuses and check runs for the exact PR head, pins the
native DeepSource App/status identities, requires every configured Python
dependency context and the unique newest App-owned `DeepSource analysis` check,
and includes a digest of that evidence in the published check. Missing,
pending, duplicated, malformed, failed, timed-out, or unavailable analysis
evidence fails closed. Any observed `DeepSource: AI Review` context is
configuration drift and fails closed; it is never ignored or counted.
`DeepSource: Test coverage` is ignored only while the trusted base config keeps
that analyzer disabled. A
pull request cannot delete or weaken its own config to bypass this gate because
activation and policy come from the protected base.

The central AI publisher does not decide whether CodeRabbit or Codex passed.
Consumer-local, default-branch source at
`.github/ci/evaluate_ai_provider.py` evaluates provider-native reviews,
App-backed deliveries, failure/usage messages, and unresolved threads. The
platform action validates and binds that evidence before publishing it.

No synthetic text envelope is a success signal. CodeRabbit requires the newest
unambiguous exact-head native review, the newest exact App-owned delivery after
that review, its successful exact-head `CodeRabbit` check from the same App,
complete review-thread pagination, zero unresolved provider threads, and no
failure, quota, or outage marker. Duplicate IDs, malformed timestamps, stale
heads, wrong Apps, skipped reviews, and incomplete pagination fail closed.
Codex has no assumed native check and remains disabled unless a protected
hosted-canary flag proves the exact native review/App-delivery shapes. Even
with that flag, only a current-head native Codex review whose complete trimmed
body is exactly `PASS`, followed by its App-owned delivery, can pass. Generic
prose alone never flips that flag.

Provider identities are closed:

- CodeRabbit review actor `coderabbitai[bot]`; delivery App ID `347564`,
  slug `coderabbitai`. Its native `CodeRabbit` check is mandatory and must be
  completed successfully on the exact head by that App; “Review skipped” never
  passes.
- Codex review actor `chatgpt-codex-connector[bot]`; delivery App ID `1144995`,
  slug `chatgpt-codex-connector`. No Codex-native check is assumed or invented,
  and the local evaluator defaults its hosted-canary gate to false.

## Trust boundary

Each profile-specific required workflow, when evaluated for a consumer
repository:

- runs on every `pull_request` and `merge_group`;
- has read-only repository permissions and no secret, OIDC, environment,
  artifact-download, cache-sharing, or write-token capability;
- cancels only obsolete runs for the same profile and pull request;
- checks out the exact target head under `target`;
- checks out `job.workflow_repository` at `job.workflow_sha` under `platform`;
- keeps bounded fast policy evaluation separate from all final-candidate
  dependency, test, security, and coverage execution.

The fast lane runs platform-owned structured-file validation or bounded Ruff
format/lint against the target bytes plus the platform secret scan. It installs
only the pinned platform toolchain; it does not install target dependencies,
import target modules, run target tests, or start the target runtime. After
Task 3 supplies a successful exact-head final admission, heavier untrusted
profile execution occurs only in read-only, repository-unprivileged OCI
containers.

The Python supervisor stages a base-SHA-bound manifest containing the protected
test policy and protected-file digests and mounts it read-only; the target
runtime does not require Git. Node Corepack manager downloads remain blocked
until pnpm 10.4.1 and Yarn 4.7.0 artifacts are digest-bound, and PowerShell
remains blocked until the Pester 5.7.1 artifact is digest-bound.

The immutable platform runner owns command construction: repository strings
are not passed to a shell, Node tests come from a protected-base per-file
manifest, mutable Pester acquisition is disabled, and Python target
dependencies are separate from the platform interpreter. The coverage lane
loads the complete test policy and protected test/support bytes from the exact
protected base, applies those selectors to the candidate head, and runs the
full suite once. Critical-ML additionally validates every mandatory
safety-hook category. These runs remain diagnostic until the trusted
target-supervisor and bounded-output blockers are closed.

The active npm runtime admits only the supported package-lock v3 subset: every
non-root package must use an official registry tarball and one canonical
SHA-512 SRI, and unknown/source-bearing lock fields fail closed. pnpm and Yarn
locks receive bounded structural YAML screening but cannot run until their
manager artifacts are digest-bound. Python Bandit receives the immutable
`contract/bandit-v1.ini` through `--ini`, preventing a candidate `.bandit`
file from changing the security selection. The Python runtime image build
context is an allowlist of its Dockerfile, exact platform requirements, three
runtime configs, and five runtime scripts; unrelated checkout bytes never
enter the Docker daemon context.

The validator compares all managed consumer controllers and the provider evaluator
against the templates shipped by the exact platform commit. It rejects mutable
actions, secret inheritance, pull-request-head execution in privileged jobs,
context spoofing, status writers, and any sixth `checks:write` job.
It also forbids every job-level reusable-workflow call in untrusted workflows:
GitHub composes the caller and called job names into a check name, so an
arbitrary pinned external workflow could otherwise synthesize a stable
required context while still appearing as the GitHub Actions App.
All unmanaged `push`, `pull_request`, `merge_group`, `workflow_dispatch`, and
`workflow_call` jobs are treated as untrusted and therefore cannot receive
secrets, a token reference, write/OIDC permission, environments, shared caches,
or downloaded artifacts. The three exact managed final-subject, resume, and
finalizer `workflow_dispatch` templates are the only exceptions: they execute
metadata-only default-branch code, bind their caller/subject identities, and
match the immutable platform templates byte-for-byte. Every other privileged
event is rejected unless it is one of the exact managed templates. The
organization required workflow itself is accepted only from `refs/heads/main`.

That static validation runs after a feature-branch push. It cannot retract a
secret already exposed by a malicious same-repository `push` workflow added in
that push. Consumer rollout therefore additionally requires repository and
organization policy that makes branch workflows secretless and unable to
obtain OIDC, environments, or write-capable tokens before default-branch
validation. This is a hard no-cutover blocker, not a claim made by the
validator.

For privileged controllers, the live pull-request API and an exact structured
run name bind the PR head/base; the run path, default-branch head/ref, actor,
triggering actor, workflow ID, run ID, and attempt independently bind the
controller source. Publishers validate both halves, repository and head
repository, GitHub Actions App ID `15368`, and the current PR. The deterministic
publisher also treats `referenced_workflows[].path` (authored selector),
`.ref` (canonical branch/tag ref), and `.sha` (resolved source) as separate
fields: it requires the reusable workflow's authored selector to be the
literal locked `@<SHA>`, the resolved SHA to match, and no branch/tag ref.
It never constructs a workflow path from `refs/heads/*`. Publishers paginate
complete histories and refuse to write if a newer same-workflow/PR/head
run—including a startup failure with no check—exists. They repeat that
freshness check before and after the write.

All five managed `pull_request_target` controller templates are filtered to base branch
`main`. Their preflight, provider evaluator, promoter, and publishers also
require the live pull request base ref to be exactly `main`, the base and head
repository identities to match the target repository, and the workflow source
to be exactly `refs/heads/main`. A PR targeting a release or feature branch
cannot invoke a privileged controller from that branch's altered workflow.

The label invalidator is now implemented as a consumer template and an
installed platform canary workflow. It runs from the exact protected-base
source on every new commit, reopen, or conversion to draft; removes both
`ci-final` and `ai-review-ready`; retries only labels still present on an
exact-head/lifecycle readback; and fails if absence cannot be proved.
The first two hosted delete canaries failed closed with HTTP 403 while the job
received `issues: write` and `pull-requests: read`. GitHub documents the PR-label
endpoint as accepting Pull requests write, so all label-mutating controller
roles now request `pull-requests: write` and no Issues permission. Repository
Issues remains disabled; broader workflow-token and PR-approval settings remain
disabled. `invalidation_controller_verified` still defaults to false until the
repaired workflow is on the protected default branch and a hosted labeled
lifecycle canary proves event delivery, both deletions, and final absence
readback.
`ready_for_review` must never re-finalize automatically. Existing checks remain
attached to an old SHA after a new commit and cannot satisfy the new head, but
same-SHA lifecycle reuse still requires external enforcement.

The REST adapter now enumerates every matching workflow run ID and every
attempt, including zero-job `startup_failure` rows, and rechecks the complete
inventory before and after label writes. Any newer failed, cancelled, queued,
or incomplete attempt blocks the selected success. This remains a hard
no-cutover blocker until hosted API fixtures prove the inventory is complete.

The new `final-subject-v1.yml` calls the reusable final workflow by immutable
platform SHA for all five supported profiles and then terminates. The narrowly
scoped `resume-finalizer-v1.yml` receives only the completed successful subject
workflow, revalidates its exact run ID, attempt, bot identity, immutable platform
SHA, current PR head, and protected base, and dispatches `finalize-python-v1.yml`.
Duplicate completion delivery reuses one rigorously validated existing controller;
manual resume reruns are rejected before dispatch.
Final gate discovery uses the three reusable workflow display names
and accepts only GitHub's optional caller-name prefix. Both subject and
controller run source SHAs must equal the captured PR base SHA; a default-branch
advance therefore blocks instead of changing trusted code mid-identity. The
controller uses GitHub Actions concurrency keyed by repository, PR, and head
with `cancel-in-progress: false`; a missing hosted-coordinator proof still
blocks locally. The post-completion handoff creates a new immutable dispatch
only after revalidating the same successful subject attempt. The broad GitHub rerun
endpoint remains forbidden because it cannot target an exact attempt safely.

`ci-final` starts deterministic final evidence; it does not directly start AI
review. After the exact-head Security and Coverage publishers both write and
read back successful, same-run, platform-owned checks, the metadata-only
`promote-ai-review` job revalidates the PR, current protected workflow source,
immutable platform source, current Actions run, complete workflow history, and
both checks. It then adds `ai-review-ready`, reads the label back, repeats the
current-head/run validation, and rolls the label back on any post-write
failure. Newest-attempt validation happens immediately before the label write.
The label can notify provider Apps, but GitHub suppresses ordinary
workflow-triggering events created with `GITHUB_TOKEN`. Consequently the three
current `pull_request_target:labeled` evaluator workflows do **not** start from
this promoter and the AI contexts cannot publish. This is a hard cutover
blocker. Conversely, a label added by a maintainer or another bot does start
those workflows but carries no proof that the promoter or deterministic gates
succeeded, so it can spend reviews prematurely. `ai-review-ready` is provider
notification only, never orchestration authority. The no-PAT repair must either
run exact-head evaluator/publisher jobs downstream in the same trusted final
workflow, or use a supported `workflow_dispatch`/`repository_dispatch` path
with promoter-bound run identity and fresh exact-head Security/Coverage
readback. No synthetic provider pass is permitted.

## Heavy final evidence

`reusable-final.yml` runs from an immutable full platform SHA with read-only
target permissions. It includes:

- Semgrep, Bandit medium/high findings, `pip-audit`, Ruff, formatting, mypy,
  warning-as-error pytest, and hashed evidence;
- repository-native `tools/sync_ci_environment.py --ci` when available;
- coverage defaults 50% global, 95% diff, and 95% critical patch;
- `coverage.critical_patch.target` and path-group floors from
  `quality_debt.yml`;
- fail-closed handling when a changed existing Python file is absent from
  coverage JSON;
- rejection of every changed line reported in coverage JSON as excluded, so
  inline `# pragma: no cover` cannot turn executable patch lines into a zero
  denominator; genuine comments and docstrings remain non-statements;
- critical-ML docstring ratchet, mandatory data-quality fixture, column
  signature audit, rebuild smoke test, path-group coverage, diff-cover, and the
  repository-native coverage ratchet.

Only the consumer coverage uploader has `id-token: write`. It checks out no
code, downloads same-run evidence, verifies every component and digest, and
then performs the Codecov OIDC upload.

## Consumer installation

Copy `templates/consumer/.github` into a target repository. Replace every
`__CI_PLATFORM_FULL_SHA__` token with the published platform commit SHA and
create:

```json
{
  "sha": "<same-full-platform-sha>",
  "contract_version": 1
}
```

at `.github/ci-platform.lock.json`. Do not substitute a branch or tag.

Every consumer also carries
`.github/ci-platform-test-policy.json`, validated against the closed
`contract/test-policy-v1.schema.json`. It contains only bounded test roots,
allowlisted marker exclusions and registrations, protected support files, the
optional `benchmark` plugin disablement, coverage module/path selectors, and
explicit leakage, lineage, model, parity, and schema test manifests. It cannot
contain a command or arbitrary pytest arguments, and
`unexpected_skip_policy` is fixed to `fail`.

The final runner loads that policy from the exact protected base commit and
applies it to the PR head, so a PR cannot weaken its own selectors. Python
profiles require test roots and coverage sources; `critical-ml` additionally
requires every critical manifest category. Its critical rerun ignores ordinary
marker exclusions, clears inherited pytest selectors, proves every declared
file collects at least one unique node, and requires the JUnit execution count
to match collection with zero skips. Global, diff, critical-patch, path-group,
native-hook, and test-manifest authority comes from the exact protected-base
`quality_debt.yml` and test policy. An independent non-regression evaluator
rejects lower floors, removed roots/sources/critical tests, new exclusions, or
disabled hooks; protected lint/test/security configuration changes require a
separately audited platform migration.

The generic frozen pre-v1 consumer fixture intentionally lacks
`registered_markers` and `protected_support_files`, so cutover remains blocked
until the first critical consumer policy is migrated and proven. Its dependency
fixture also contains a non-exact registry bound, demonstrating that a legacy
requirements-plus-constraints graph must be normalized into the closed
platform manifest contract rather than admitted as arbitrary network input.

Set the numeric repository variable `CI_REQUIRED_WORKFLOW_ID` to the workflow
ID of the organization ruleset `CI / required` workflow. The final preflight
uses that immutable ID—not a name search—to verify the newest successful fast
run and exact GitHub Actions job/check binding.

CodeRabbit organization settings and `.coderabbit.yaml` must both disable
automatic and incremental review, use the `ai-review-ready` label, disable
draft review, and keep Autofix off. No `CODERABBIT_AUTOFIX_TOKEN` is permitted.
CodeRabbit reviews are final-only; the $0.25/file usage add-on, recurring
credit purchases, and automatic top-up are disabled, and rate-limit exhaustion
waits fail closed without a provider PASS. Codex remains exact-head/final-only with purchased credits,
automatic reload, and overage disabled; quota exhaustion likewise waits fail
closed. DeepSource automatic AI recharge and every pooled-credit AI feature
remain disabled. All three policies require hosted resolved-settings readback
before their contexts can be required.

The consumer template ships one exact root `.coderabbit.yaml`: assertive,
label-only review; no draft or incremental review; closed bot exclusions; and
Autofix plus every other write-capable finishing touch disabled. The integrity
validator requires byte-equivalence to that template, preflight classifies any
change as `critical-ml`, and protected-policy comparison prevents a PR from
weakening it. CodeRabbit organization/global overrides have higher precedence,
so hosted resolved-configuration readback remains mandatory before cutover.

## Required GitHub configuration and rollout

The following separates the approved public pre-release publication from the
still-deferred production cutover. While
`x-rollout-status.cutover_permitted` is false, only steps explicitly marked as
pre-release canary work are authorized:

1. **Pre-release canary work:** publish only a sanitized root snapshot to the
   approved public repository. Never push this staging repository's reachable
   history. Verify the public tree against `contract/public-prerelease-v1.json`
   before and after publication. Do not introduce a PAT.

   Export the exact Git blob bytes with conversion disabled; this is the only
   supported public-snapshot boundary. Set the source and archive variables to
   absolute paths, and keep `ARCHIVE_PATH` outside the sanitized source tree so
   the archive cannot contaminate the attested publication inventory:

   ```bash
   SANITIZED_SOURCE="/absolute/path/to/canonical-sanitized-source"
   ARCHIVE_PATH="/absolute/path/outside/canonical-sanitized-source/ci-platform-public.tar"
   SANITIZED_ROOT_SHA="$(git -C "$SANITIZED_SOURCE" rev-parse --verify HEAD^{commit})"
   git -C "$SANITIZED_SOURCE" -c core.autocrlf=false archive --format=tar --output="$ARCHIVE_PATH" "$SANITIZED_ROOT_SHA"
   ```

   Extract that archive into a gitless directory and run the structural
   validator there before publication. Plain archives or working-tree copies
   whose bytes have been transformed by checkout settings are not canonical:
   autocrlf-transformed checkouts must fail closed on the publication
   attestation. Do not normalize transformed bytes or replace the attested
   mode, path, and content digest with a checkout-specific value.
2. **Pre-release canary work:** protect its default branch with pull requests, CODEOWNERS, resolved
   conversations, stale-approval dismissal, and no force push or deletion.
3. After the bootstrap merge, disable `merge-gate-v1.yml`,
   `merge-gate-python-v1.yml`, `merge-gate-node-v1.yml`,
   `merge-gate-powershell-v1.yml`, and `merge-gate-critical-ml-v1.yml` in the
   `koios-ai/ci-platform` Actions UI. Read back all five disabled states and
   verify `continuous-validation.yml` remains enabled before any consumer
   ruleset leaves Evaluate mode. Disabling the source workflows does not
   replace the five organization ruleset mappings.
4. Promote the canary-only attestation into a protected supported-release
   manifest before the first consumer pin. Each allowed full SHA must carry
   closed digests for its exact controller templates, evaluator, and
   CodeRabbit policy. Keep old releases supported during critical → hobby →
   professional canaries, then retire them deliberately; never accept
   arbitrary historical SHAs.
5. Require GitHub-authored actions plus the pinned Codecov action, and enforce
   full-length action SHAs.
6. After every blocker in `x-rollout-status` is removed and re-audited, create
   the five non-overlapping organization required-workflow rules from
   `x-merge-gate-v1.profile_rulesets`. Each
   `props.ci_profile:<profile>` target must require only its matching immutable
   merge-gate workflow on `~DEFAULT_BRANCH`. Assign `ci_profile` explicitly;
   do not rely on a default, inheritance, or an empty value. Start all five in
   Evaluate mode and use a named, audited break-glass actor only.
7. Only after the same gate, require all six contexts in `contract/v1.json`,
   bound to their observed
   publishers where GitHub supports source binding.
8. Require the strict “branch must be up to date” ruleset setting. Until every
   required context is produced for a synthetic merge-group SHA, this is the
   only hosted rule preventing an unchanged PR head from reusing evidence that
   was bound internally to an older base SHA.
9. Do **not** enable a merge-queue rule during the initial rollout. Only
   `CI / required` currently binds the synthetic merge-group SHA; the five
   final Security, Coverage, and AI contexts are intentionally bound to the PR
   head. Requiring all six on a merge queue now would deadlock it.
10. Keep paid Actions overage disabled. Budget exhaustion must stop merges.
11. Canary one critical repository, one hobby repository, and one professional
    repository before organization-wide rollout.

The hosted canary must prove a real job starts and completes. It must cover
docs-only, Python, critical-ML, dependency, draft-to-ready, rapid multi-push,
workflow tampering, provider timeout, budget exhaustion, protected `main`, and
scheduled validation. A
zero-job `startup_failure` run is not recovery. The platform-source checkout
and the observed `job.workflow_*` values must also be captured because private
cross-repository access is not proven by local tests.
The canary must also include an application-Python change with no changed test
file and a changed-test case: the first must not fall back to an unprovisioned
full suite, while the second must prove protected selection, repository
dependency synchronization, `pip check`, real test collection, and zero
skips.

For a repository already using DeepSource, retain its existing local
DeepSource wrapper as a required rollback gate until the central
`Security / required` check has passed a hosted exact-head canary that includes
all configured SCA contexts and provider identity readback. Only then remove
the duplicate wrapper in the same ruleset cutover. A local test cannot prove
hosted DeepSource delivery.

All five mapped merge-gate workflows retain the unfiltered `merge_group`
trigger. Their pure policy binds the synthetic SHA and immutable profile/path
pair but fails AI admission closed behind
`merge-group-ai-mapping-canary`. Production merge queue remains blocked until a
hosted mapping proves the associated queued PR evidence. PR-head AI success must never be copied or relabeled
onto a merge group.

## Local verification

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"
.\scripts\run-tests.ps1 tests -q
ruff check . --no-cache
ruff format --check . --no-cache
```

On Linux, run the same hermetic test harness with
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHON=python3 bash scripts/run-tests.sh tests -q`.

## Deliberate limitations

- A sanitized public pre-release may exist for hosted canaries. Its checks are
  non-authoritative and it is not a supported consumer release.
- Cutover is explicitly blocked. The current same-repository Actions design
  cannot invalidate older successful manual contexts when a newer same-SHA
  attempt dies before any job starts. Label deletion also cannot erase old
  same-SHA required checks after close-to-reopen or draft-to-ready transitions.
- Isolated target containers still own their scratch evidence and can forge
  expected files or exhaust the bind-mounted output filesystem. A trusted,
  bounded target supervisor and fresh reconstruction are required before any
  runtime result can become admission authority.
- The fast affected-test lane is also blocked until a protected supervisor
  proves the selected tests, and strict mypy needs a hosted adoption ratchet
  for existing consumers.
- The first critical consumer still needs both the closed v1 test-policy
  migration and a canonical requirements-plus-constraints manifest contract.
- Dependabot has no closed non-paid-AI admission controller yet; dependency PRs
  remain blocked instead of receiving synthetic AI passes. Any future
  exemption must bind exact actor, event sender, repository, PR number,
  base/head SHAs, and the full copy/rename/delete-aware dependency diff.
- Fork pull requests are excluded from v1 rather than ambiguously checked out.
- Protected-main push and scheduled structural validation are separate in
  `continuous-validation.yml`; hosted heavy-validation proof remains blocked.
- A newly added same-repository feature-branch `push` workflow can execute
  before this default-branch validator sees it. Organization/repository Actions
  policy and secret placement must make that first execution harmless; this
  has not been hosted-proven.
- Hosted provider delivery, Codecov OIDC, ruleset source binding, merge queue,
  public platform source identity, DeepSource exact-head delivery, and App
  ownership require live canaries.
- CodeRabbit native review/App/check evidence and Codex native review/App
  evidence still need hosted canaries. Codex remains disabled, and no generic
  bot comment, completion state, or synthetic envelope is a substitute for the
  exact current native review result `PASS`.
- Finalization now has local production-shaped source attestation, complete
  GraphQL review-thread/nested-comment pagination, complete same-head attempt
  inventory, exact-attempt dispatch/resume, an installed invalidation canary,
  and non-cancelling GitHub-native concurrency. None is cutover authority until
  live API/event/concurrency readbacks prove those semantics and all
  hosted-verification flags are enabled from protected configuration.
- GitHub Code Quality still needs authenticated organization `No repositories`
  enforcement and billing-cessation receipts; the disabled UI alone is not
  completion evidence.
- Node Corepack manager artifacts (pnpm 10.4.1 and Yarn 4.7.0) and the
  PowerShell Pester 5.7.1 artifact still need immutable digest binding.
- The control-plane selects Python 3.12.13, but `requirements-dev.txt` has exact
  versions without artifact hashes. Release requires a hash-locked
  `--require-hashes` install or a digest-pinned prebuilt platform image.
- The active source-bound merge gate checks out the platform source separately.
  The old required/reusable-final workflows are inactive legacy evidence, not
  v1 candidates. Public publication is authorized only for a sanitized root
  snapshot and non-authoritative hosted source-identity canaries; PAT fallback
  is forbidden.
- The validator currently authenticates only a consumer pin equal to the active
  platform workflow SHA. That cannot support sequential fleet rollout: any
  platform commit would break every older consumer. A protected bounded release
  manifest with exact template digests is required before any consumer pin or
  production rollout.
- The promoter's `GITHUB_TOKEN` label mutation cannot trigger the three current
  label-event evaluator workflows. Their CodeRabbit, Codex, and aggregate
  contexts remain unreachable until the cadence is co-located in the trusted
  final workflow or moved to a supported exact-head-revalidated dispatch
  event. Labels written by other actors are not trusted promoter provenance and
  must not become orchestration authority. A PAT is not an acceptable repair.
- Initial rollout explicitly excludes merge queue; enabling it before all six
  contexts bind the synthetic SHA is a fail-closed cutover blocker.
- GitHub billing and Actions availability must be repaired before any
  externally green result is treated as deterministic CI.
