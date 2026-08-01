from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from collections.abc import Callable
from functools import cache
from pathlib import Path
from types import ModuleType

import jsonschema
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_ci_platform_v1.py"
REPOSITORY = "koios-ai/example"
SOURCE_SHA = "a" * 40
CONFIG_DIGEST = "9" * 64
OBSERVED_AT = "2026-07-27T12:00:00Z"
ATTESTATION_ALGORITHM = "rsa-pkcs1v15-sha256"
ATTESTATION_ISSUER = "koios-ci-platform-v1"
ATTESTATION_KEY_ID = "koios-ci-deepsource-canary-2026-07"
ATTESTATION_PUBLIC_KEY_SHA256 = "05a24f80bce15e0b4b68269ac01548c6c448c0230076f08d6b40b19423ae4af4"
ATTESTATION_SIGNATURE = (
    "NHx2DIRgdHdqw5fLxN3nGv16Sh+wdWpgkx2OjKIv69nicXodxmZWPh6bH0snIGskSO/8OKyjFzDEjp6bptG/ECqGovw6s4SuJHgS"
    "7DLiEoUu03MczzkrJEsLMWfoaCA+dLfAHqBUcTUs3dLYWnYhGpHS01GfnHWbyTiOBoPOiPjWqQmw/VlgAgBja2ECHsDYAQESJR0E"
    "BiUqaTK5ubZeg/Jwd56a6PcGmBOze7q28+CT5ctNh2Ehk+4RlTa/erfclE7bsZh7ha+4aWn0gAJpUVQ3PkSQXRax38mhhCVUlfiJ"
    "PoPbEYn+4LCrOhABNJSHLPMe3+Kg7p5wNjXPYz+PcA=="
)
DEEPSOURCE_APP = {"id": 16372, "slug": "deepsource-io"}
DEEPSOURCE_EXPECTED_CHECKS = [
    "DeepSource analysis",
    "DeepSource: Secrets",
    "DeepSource: requirements.txt",
    "DeepSource: requirements-core-next.txt",
    "DeepSource: requirements-compat-ag.txt",
    "DeepSource: requirements-maintenance.txt",
]
DEEPSOURCE_DISABLED_CHECKS = ["DeepSource: AI Review", "DeepSource: Test coverage"]
DEEPSOURCE_STATIC_RULE_IDS = ["call-arg", "attr-defined", "assignment", "operator", "unreachable"]
DEEPSOURCE_SCA_CAPABILITIES = ["reachability", "dynamic-risk", "epss", "cvss", "license-compliance"]
DEEPSOURCE_SIGNAL_CHECKS = {
    "python-static-quality": ["DeepSource analysis"],
    "ruff-transformer": ["DeepSource analysis"],
    "sca": [
        "DeepSource: requirements.txt",
        "DeepSource: requirements-core-next.txt",
        "DeepSource: requirements-compat-ag.txt",
        "DeepSource: requirements-maintenance.txt",
    ],
    "secrets": ["DeepSource: Secrets"],
    "docker-compose-config": ["DeepSource analysis"],
    "adapter-integrity": DEEPSOURCE_EXPECTED_CHECKS,
    "ai-review-readback": ["DeepSource: AI Review"],
    "coverage": ["DeepSource: Test coverage"],
}
PROFILE_WORKFLOWS = {
    "baseline": "merge-gate-v1.yml",
    "python": "merge-gate-python-v1.yml",
    "node": "merge-gate-node-v1.yml",
    "powershell": "merge-gate-powershell-v1.yml",
    "critical-ml": "merge-gate-critical-ml-v1.yml",
}
SOURCE_REPOSITORY = "koios-ai/ci-platform"
SOURCE_REPOSITORY_GUARD = f"github.repository != '{SOURCE_REPOSITORY}'"
SOURCE_DISABLED_JOB_NAMES = {profile: f"Koios CI / {profile} consumer gate disabled" for profile in PROFILE_WORKFLOWS}


def consumer_terminal_job_name(profile: str) -> str:
    return (
        "${{ github.repository == 'koios-ai/ci-platform' "
        f"&& 'Koios CI / {profile} consumer gate disabled' || 'CI / required' }}}}"
    )


@cache
def load_validator() -> ModuleType:
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location("validate_ci_platform_v1", VALIDATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_deepsource_fixture(fixture: Path) -> None:
    module = load_validator()
    module.validate_deepsource_parity(
        fixture,
        as_of=module.dt.datetime(2026, 7, 27, 13, tzinfo=module.dt.UTC),
    )


def run_validator(
    root: Path,
    *,
    as_of: str | None = None,
    process_boundary: bool = False,
) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(VALIDATOR), "--root", str(root)]
    if as_of is not None:
        command.extend(("--as-of", as_of))
    if process_boundary:
        return subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    validator = load_validator()
    try:
        raw_as_of = as_of or validator.dt.datetime.now(validator.dt.UTC).isoformat()
        effective_as_of = validator.dt.datetime.fromisoformat(raw_as_of.replace("Z", "+00:00"))
        if effective_as_of.tzinfo is None:
            raise ValueError("--as-of must include a timezone")
        validator.validate_workflow(root)
        validator.validate_profile_contract(root, as_of=effective_as_of)
        validator.validate_common_security(root)
        validator.validate_quality_map(root)
        validator.validate_deepsource_parity(root, as_of=effective_as_of)
        validator.validate_publication_boundary(root)
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        return subprocess.CompletedProcess(command, 1, "", f"{error}\n")
    return subprocess.CompletedProcess(
        command,
        0,
        "LOCAL STRUCTURAL VALIDATION ONLY: independent hosted/evidence review remains required\n",
        "",
    )


def copy_contract_fixture(tmp_path: Path) -> Path:
    fixture = tmp_path / "platform"
    for relative in (
        ".github/workflows/merge-gate-v1.yml",
        ".github/workflows/merge-gate-python-v1.yml",
        ".github/workflows/merge-gate-node-v1.yml",
        ".github/workflows/merge-gate-powershell-v1.yml",
        ".github/workflows/merge-gate-critical-ml-v1.yml",
        ".github/workflows/continuous-validation.yml",
        ".github/workflows/required.yml",
        ".github/workflows/reusable-final.yml",
        "contract/v1.json",
        "contract/public-prerelease-v1.json",
        "contract/mypy-v1.ini",
        "contract/ruff-v1.toml",
        "contract/deterministic-quality-v1.json",
        "contract/deepsource-parity-v1.schema.json",
        "contract/secret-scan-v1.json",
        "scripts/run_quality_canaries.py",
        "scripts/merge_gate_policy.py",
        "scripts/profile_runner.py",
        "scripts/generate_merge_gate_profiles.py",
        "scripts/secret_scan.py",
        "templates/consumer/.github/ci-platform-deepsource-parity.json",
    ):
        source = ROOT / relative
        target = fixture / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    shutil.copytree(ROOT / "tests/canaries/quality", fixture / "tests/canaries/quality")
    shutil.copytree(ROOT / "tests/canaries/secrets", fixture / "tests/canaries/secrets")
    manifest_path = fixture / "contract/public-prerelease-v1.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact_count, artifact_digest = load_validator()._publication_tree_attestation(fixture)
    manifest["artifact_count"] = artifact_count
    manifest["artifact_tree_sha256"] = artifact_digest
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return fixture


def test_v1_contract_validator_rejects_the_explicitly_blocked_parity_template(tmp_path: Path) -> None:
    """Catches treating an unverified consumer template as DeepSource disposition proof."""
    result = run_validator(copy_contract_fixture(tmp_path))

    assert result.returncode != 0
    assert "disposition is blocked" in result.stderr


def test_v1_contract_validator_rejects_an_unowned_quality_class(tmp_path: Path) -> None:
    """Catches a historical Code Quality signal silently becoming native-only."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / "contract/deterministic-quality-v1.json"
    quality_map = json.loads(path.read_text(encoding="utf-8"))
    quality_map["classes"]["wrong-arguments"]["owner"] = "native-only"
    path.write_text(json.dumps(quality_map), encoding="utf-8")

    result = run_validator(fixture, as_of="2026-07-27T13:00:00Z")

    assert result.returncode != 0
    assert "native-only" in result.stderr


def test_in_process_validator_calls_isolate_roots_and_diagnostics(tmp_path: Path) -> None:
    """Catches validator module reuse leaking one mutated fixture into the next."""
    first_root = tmp_path / "first-fixture"
    scripts = first_root / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "merge_gate_policy.py").write_text("", encoding="utf-8")
    (scripts / "profile_runner.py").write_text("", encoding="utf-8")
    first_result = run_validator(
        first_root,
        as_of="2026-07-27T13:00:00Z",
        process_boundary=False,
    )
    assert first_result.returncode != 0
    assert str(first_root) in first_result.stderr.replace("\\\\", "\\")

    second_root = tmp_path / "second-fixture"
    second_root.mkdir()
    second_result = run_validator(
        second_root,
        as_of="2026-07-27T13:00:00Z",
        process_boundary=False,
    )
    assert second_result.returncode != 0
    assert "authoritative merge-gate scripts are missing" in second_result.stderr
    assert str(first_root) not in second_result.stderr

    timezone_result = run_validator(
        first_root,
        as_of="2026-07-27T13:00:00",
        process_boundary=False,
    )
    assert timezone_result.returncode != 0
    assert "timezone" in timezone_result.stderr
    assert str(first_root) not in timezone_result.stderr
    assert str(second_root) not in timezone_result.stderr


def test_platform_validator_cli_has_success_and_diagnostic_failure_boundaries(tmp_path: Path) -> None:
    """Catches an in-process test helper masking the executable CLI contract."""
    help_result = subprocess.run(
        [sys.executable, str(VALIDATOR), "--help"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert help_result.returncode == 0
    assert "--structural-only" in help_result.stdout

    failure_result = run_validator(tmp_path / "missing", process_boundary=True)
    assert failure_result.returncode != 0
    assert failure_result.stderr.strip()


def test_deterministic_quality_map_permanently_excludes_github_code_quality() -> None:
    """Catches the replacement map retaining a future Code Quality activation path."""
    quality = json.loads((ROOT / "contract/deterministic-quality-v1.json").read_text(encoding="utf-8"))

    assert quality["github_code_quality"] == {
        "enabled": False,
        "policy": "permanent-exclusion",
        "contexts": [],
        "workflows": [],
        "extensions": [],
        "configurations": [],
        "canaries": [],
        "organization_repository_access_required": "no-repositories",
        "organization_repository_access_enforcement_required": True,
        "reactivation_permitted": False,
    }


def complete_parity_fixture() -> dict[str, object]:
    """A hand-audited synthetic consumer that has every required hosted proof."""
    signals: list[dict[str, object]] = [
        {
            "id": "python-static-quality",
            "parity_status": "proven",
            "gaps": [],
            "central_owner": "strict-mypy",
            "command": "mypy --strict --warn-unreachable",
            "pinned_tool_version": "mypy==1.19.1",
            "pinned_config_digest": "b" * 64,
            "scope": "src/**/*.py",
            "positive_canary": "tests/canaries/python-static/pass.py",
            "negative_canary": "tests/canaries/python-static/fail.py",
            "hosted_inventory": "artifacts/python-rules.json",
            "rule_ids": DEEPSOURCE_STATIC_RULE_IDS,
            "severity_threshold": "warning",
            "quality_threshold": "zero-findings",
        },
        {
            "id": "ruff-transformer",
            "parity_status": "proven",
            "gaps": [],
            "central_owner": "ruff",
            "command": "ruff check .",
            "pinned_tool_version": "ruff==0.14.14",
            "pinned_config_digest": "c" * 64,
            "scope": "src/**/*.py",
            "positive_canary": "tests/canaries/ruff/pass.py",
            "negative_canary": "tests/canaries/ruff/fail.py",
            "hosted_inventory": "artifacts/ruff-rules.json",
            "transformer_version": "1",
            "ruff_version": "0.14.14",
            "config_digest": "c" * 64,
        },
        {
            "id": "sca",
            "parity_status": "proven",
            "gaps": [],
            "central_owner": "osv-scanner",
            "command": "osv-scanner --lockfile requirements-dev.txt",
            "pinned_tool_version": "osv-scanner==2.0.3",
            "pinned_config_digest": "d" * 64,
            "scope": "all dependency manifests",
            "positive_canary": "tests/canaries/sca/pass.lock",
            "negative_canary": "tests/canaries/sca/vulnerable.lock",
            "hosted_inventory": "artifacts/sca-inventory.json",
            "canonical_constraints": "constraints.txt",
            "optional_conda_surfaces": [
                {"path": "environment.yml", "present": False},
                {"path": "environment.yaml", "present": False},
                {"path": "conda-lock.yml", "present": False},
            ],
            "manifests": [
                {
                    "path": "requirements.txt",
                    "profiles": ["python", "critical-ml"],
                    "resolved_graph": "artifacts/requirements.graph.json",
                    "sbom": "artifacts/requirements.cdx.json",
                },
                {
                    "path": "constraints.txt",
                    "profiles": ["python", "critical-ml"],
                    "resolved_graph": "artifacts/constraints.graph.json",
                    "sbom": "artifacts/constraints.cdx.json",
                },
                {
                    "path": "requirements-core-next.txt",
                    "profiles": ["python", "critical-ml"],
                    "resolved_graph": "artifacts/requirements-core-next.graph.json",
                    "sbom": "artifacts/requirements-core-next.cdx.json",
                },
                {
                    "path": "requirements-compat-ag.txt",
                    "profiles": ["critical-ml"],
                    "resolved_graph": "artifacts/requirements-compat-ag.graph.json",
                    "sbom": "artifacts/requirements-compat-ag.cdx.json",
                },
                {
                    "path": "requirements-maintenance.txt",
                    "profiles": ["baseline", "python", "critical-ml"],
                    "resolved_graph": "artifacts/requirements-maintenance.graph.json",
                    "sbom": "artifacts/requirements-maintenance.cdx.json",
                },
                {
                    "path": "package-lock.json",
                    "profiles": ["node"],
                    "resolved_graph": "artifacts/package-lock.graph.json",
                    "sbom": "artifacts/package-lock.cdx.json",
                },
                {
                    "path": "powershell.lock.json",
                    "profiles": ["powershell"],
                    "resolved_graph": "artifacts/powershell.graph.json",
                    "sbom": "artifacts/powershell.cdx.json",
                },
            ],
        },
        {
            "id": "secrets",
            "parity_status": "proven",
            "gaps": [],
            "central_owner": "gitleaks",
            "command": "gitleaks detect --redact",
            "pinned_tool_version": "gitleaks==8.24.2",
            "pinned_config_digest": "e" * 64,
            "scope": "git history and working tree",
            "positive_canary": "tests/canaries/secrets/pass.txt",
            "negative_canary": "tests/canaries/secrets/composed-at-runtime",
            "hosted_inventory": "artifacts/secrets-scope.json",
            "scan_scope": ["history", "working-tree"],
            "provider_trigger_gaps": ["documentation", "configuration"],
        },
        {
            "id": "docker-compose-config",
            "parity_status": "proven",
            "gaps": [],
            "central_owner": "trivy",
            "command": "trivy config --exit-code 1 .",
            "pinned_tool_version": "trivy==0.59.1",
            "pinned_config_digest": "f" * 64,
            "scope": "Dockerfile, Compose, and deployment config",
            "positive_canary": "tests/canaries/config/pass.yml",
            "negative_canary": "tests/canaries/config/insecure.yml",
            "hosted_inventory": "artifacts/config-scope.json",
            "config_scope": ["Dockerfile", "compose.yml", "k8s/**/*.yml"],
        },
        {
            "id": "adapter-integrity",
            "parity_status": "proven",
            "gaps": [],
            "central_owner": "platform-adapter-integrity",
            "command": "koios-ci deepsource-adapter-canary --closed-inventory",
            "pinned_tool_version": "koios-ci==1.0.0",
            "pinned_config_digest": "3" * 64,
            "scope": "DeepSource App and status adapter mapping",
            "positive_canary": "tests/canaries/adapter/complete.json",
            "negative_canary": "tests/canaries/adapter/missing-check.json",
            "hosted_inventory": "artifacts/adapter-inventory.json",
            "adapter_contract_digest": "4" * 64,
            "hosted_app": {"id": 16372, "slug": "deepsource-io"},
        },
        {
            "id": "ai-review-readback",
            "parity_status": "proven",
            "gaps": [],
            "central_owner": "provider-readback",
            "command": "koios-ci status --json",
            "pinned_tool_version": "koios-ci==1.0.0",
            "pinned_config_digest": "1" * 64,
            "scope": "provider application configuration",
            "positive_canary": "tests/canaries/ai-review/enabled.json",
            "negative_canary": "tests/canaries/ai-review/disabled.json",
            "hosted_inventory": "artifacts/ai-review-readback.json",
            "enabled_readback": False,
            "disabled_readback": True,
        },
        {
            "id": "coverage",
            "parity_status": "proven",
            "gaps": [],
            "central_owner": "coverage-policy",
            "command": "python scripts/evaluate_coverage.py",
            "pinned_tool_version": "coverage==7.6.9",
            "pinned_config_digest": "2" * 64,
            "scope": "repository executable Python",
            "positive_canary": "tests/canaries/coverage/at-floor.xml",
            "negative_canary": "tests/canaries/coverage/below-floor.xml",
            "hosted_inventory": "artifacts/coverage-readback.json",
            "applicable": False,
            "not_applicable_reason": "hosted provider coverage was disabled",
        },
    ]
    for signal in signals:
        signal["outcome"] = "retain-unique-defense-in-depth"
    next(signal for signal in signals if signal["id"] == "ai-review-readback")["outcome"] = "disable-usage-based-ai"
    next(signal for signal in signals if signal["id"] == "coverage")["outcome"] = "replace-proven-duplicate"
    return {
        "schema_version": 2,
        "template_status": "complete",
        "repository": REPOSITORY,
        "source_config_sha": SOURCE_SHA,
        "source_config_digest": CONFIG_DIGEST,
        "hosted_inventory_artifact": "artifacts/hosted-inventory.json",
        "hosted_inventory_observed_at": OBSERVED_AT,
        "profiles": ["baseline", "python", "node", "powershell", "critical-ml"],
        "signals": signals,
        "disposition_preconditions": {
            "all_signals_proven": True,
            "live_ruleset_safe": None,
            "app_subscription_readbacks": None,
        },
    }


def receipt(root: Path, relative: str, content: object) -> dict[str, object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(content, sort_keys=True) + "\n").encode()
    path.write_bytes(payload)
    return {"path": relative, "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}


def byte_receipt(root: Path, relative: str, payload: bytes) -> dict[str, object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return {"path": relative, "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def hosted_state_receipt(surface: str, state: dict[str, object]) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": "koios-ci/hosted-state-receipt-v1",
        "source": {"organization": "koios-ai", "surface": surface},
        "captured_at": OBSERVED_AT,
        "authentication": {"authenticated": True, "method": "github-api"},
        "reviewer": {"login": "hosted-auditor", "id": 42, "type": "User"},
        "provider": {"name": "GitHub", "domain": "github.com"},
        "state": state,
    }
    payload["sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return payload


def materialize_complete_parity(fixture: Path) -> dict[str, object]:
    parity = complete_parity_fixture()
    evidence = fixture / "evidence"
    evidence.mkdir()
    schema = json.loads((fixture / "contract/deepsource-parity-v1.schema.json").read_text(encoding="utf-8"))
    expectations = schema["x-koios-ci-canary-expectations-v1"]["signals"]
    parity["evidence_root"] = "evidence"
    reviewer = {"login": "hosted-auditor", "id": 42, "type": "User"}
    source = {"repository": REPOSITORY, "sha": SOURCE_SHA}
    authentication = {"authenticated": True, "method": "provider-api"}
    provider = {"name": "DeepSource", "app": DEEPSOURCE_APP}
    preconditions = parity["disposition_preconditions"]
    assert isinstance(preconditions, dict)
    preconditions["live_ruleset_safe"] = receipt(
        evidence,
        "readbacks/live-ruleset.json",
        {
            "schema": "koios-ci/deepsource-live-ruleset-readback-v1",
            "source": source,
            "captured_at": OBSERVED_AT,
            "authentication": authentication,
            "reviewer": reviewer,
            "provider": provider,
            "state": {
                "transition_safe": True,
                "required_context": "Security / required",
                "deepsource_required": True,
            },
        },
    )
    preconditions["app_subscription_readbacks"] = receipt(
        evidence,
        "readbacks/app-subscription.json",
        {
            "schema": "koios-ci/deepsource-app-subscription-readback-v1",
            "source": source,
            "captured_at": OBSERVED_AT,
            "authentication": authentication,
            "reviewer": reviewer,
            "provider": provider,
            "state": {
                "app_state": "retained",
                "subscription_state": "team-fixed-active",
                "usage_based_ai_enabled": False,
            },
        },
    )
    parity["source_config_receipt"] = receipt(
        evidence,
        "source-config.json",
        {
            "schema": "koios-ci/deepsource-source-config-v1",
            "source": source,
            "config_digest": CONFIG_DIGEST,
            "analyzers": [
                {"name": "python", "enabled": True},
                {"name": "secrets", "enabled": True},
                {"name": "test-coverage", "enabled": False},
            ],
            "captured_at": OBSERVED_AT,
            "reviewer": reviewer,
        },
    )
    signal_ids = [str(item["id"]) for item in parity["signals"]]
    parity["hosted_inventory_artifact"] = receipt(
        evidence,
        "hosted-inventory.json",
        {
            "schema": "koios-ci/deepsource-hosted-inventory-v1",
            "repository": REPOSITORY,
            "source_sha": SOURCE_SHA,
            "signal_ids": signal_ids,
            "provider_app": DEEPSOURCE_APP,
            "expected_checks": [
                {"name": name, "state": "success", "app": DEEPSOURCE_APP} for name in DEEPSOURCE_EXPECTED_CHECKS
            ],
            "disabled_checks": [
                {"name": name, "state": "disabled", "app": DEEPSOURCE_APP} for name in DEEPSOURCE_DISABLED_CHECKS
            ],
            "observed_at": OBSERVED_AT,
            "reviewer": reviewer,
            "source": source,
        },
    )
    signals = parity["signals"]
    assert isinstance(signals, list)
    attested_canaries: list[dict[str, object]] = []
    attested_item_canaries: list[dict[str, object]] = []
    for index, signal in enumerate(signals):
        assert isinstance(signal, dict)
        signal_id = str(signal["id"])
        provider_item_ids: list[str] | None = None
        if signal_id == "python-static-quality":
            provider_item_ids = DEEPSOURCE_STATIC_RULE_IDS
        elif signal_id == "sca":
            provider_item_ids = DEEPSOURCE_SCA_CAPABILITIES
        inventory_payload: dict[str, object] = {
            "schema": "koios-ci/deepsource-signal-inventory-v1",
            "repository": REPOSITORY,
            "source_sha": SOURCE_SHA,
            "signal_id": signal_id,
            "provider_signal_id": f"deepsource/{signal_id}",
            "provider_app": DEEPSOURCE_APP,
            "provider_check_names": DEEPSOURCE_SIGNAL_CHECKS[signal_id],
            "observed_at": OBSERVED_AT,
            "reviewer": reviewer,
            "source": source,
        }
        if provider_item_ids is not None:
            inventory_payload["provider_item_ids"] = provider_item_ids
        signal["hosted_inventory"] = receipt(
            evidence,
            f"signals/{index}/inventory.json",
            inventory_payload,
        )
        for kind in ("positive", "negative"):
            expectation = expectations[signal_id][kind]
            exit_code = expectation["exit"]
            fixture_payload = f"{signal_id}:{kind}\n".encode()
            fixture_relative = f"fixtures/{index}/{kind}.txt"
            fixture_path = evidence / fixture_relative
            fixture_path.parent.mkdir(parents=True, exist_ok=True)
            fixture_path.write_bytes(fixture_payload)
            fixture_receipt = {
                "path": fixture_relative,
                "sha256": hashlib.sha256(fixture_payload).hexdigest(),
                "bytes": len(fixture_payload),
            }
            canary_payload = {
                "schema": "koios-ci/deepsource-canary-result-v1",
                "signal_id": signal_id,
                "canary_kind": kind,
                "owner": {
                    "tool": signal["central_owner"],
                    "version": signal["pinned_tool_version"],
                    "config_digest": signal["pinned_config_digest"],
                },
                "expected_exit": exit_code,
                "actual_exit": exit_code,
                "fixture": fixture_receipt,
                "executed_at": OBSERVED_AT,
                "stdout": byte_receipt(
                    evidence,
                    f"captures/{index}/{kind}.stdout",
                    f"{signal_id}:{kind}:stdout".encode(),
                ),
                "stderr": byte_receipt(
                    evidence,
                    f"captures/{index}/{kind}.stderr",
                    f"{signal_id}:{kind}:diagnostic".encode(),
                ),
                "reviewer": reviewer,
                "source": source,
            }
            signal[f"{kind}_canary"] = receipt(
                evidence,
                f"signals/{index}/{kind}.json",
                canary_payload,
            )
            attested_canaries.append(
                {
                    key: canary_payload[key]
                    for key in (
                        "signal_id",
                        "canary_kind",
                        "owner",
                        "expected_exit",
                        "actual_exit",
                        "fixture",
                        "executed_at",
                        "stdout",
                        "stderr",
                    )
                }
                | {
                    "command": signal["command"],
                    "scope": signal["scope"],
                }
            )
        item_ids: list[str] = []
        mapping_field = ""
        if signal_id == "python-static-quality":
            item_ids = DEEPSOURCE_STATIC_RULE_IDS
            mapping_field = "rule_mappings"
        elif signal_id == "sca":
            item_ids = DEEPSOURCE_SCA_CAPABILITIES
            mapping_field = "capability_mappings"
        if mapping_field:
            mappings: list[dict[str, object]] = []
            for item_index, item_id in enumerate(item_ids):
                fixture_receipt = byte_receipt(
                    evidence,
                    f"signals/{index}/items/{item_index}.fixture",
                    f"{signal_id}:{item_id}:fixture\n".encode(),
                )
                stdout_receipt = byte_receipt(
                    evidence,
                    f"signals/{index}/items/{item_index}.stdout",
                    f"{signal_id}:{item_id}:stdout".encode(),
                )
                diagnostic = f"{signal_id}:{item_id}:negative".encode()
                stderr_receipt = byte_receipt(
                    evidence,
                    f"signals/{index}/items/{item_index}.stderr",
                    diagnostic,
                )
                item_canary = {
                    "schema": "koios-ci/deepsource-disposition-negative-canary-v1",
                    "repository": REPOSITORY,
                    "source_sha": SOURCE_SHA,
                    "signal_id": signal_id,
                    "provider_item_id": item_id,
                    "owner": {
                        "tool": signal["central_owner"],
                        "version": signal["pinned_tool_version"],
                        "config_digest": signal["pinned_config_digest"],
                    },
                    "command": signal["command"],
                    "fixture": fixture_receipt,
                    "stdout": stdout_receipt,
                    "stderr": stderr_receipt,
                    "diagnostic_stream": "stderr",
                    "diagnostic_sha256": hashlib.sha256(diagnostic).hexdigest(),
                    "expected_exit": 1,
                    "actual_exit": 1,
                    "executed_at": OBSERVED_AT,
                    "attested_parent_negative_canary_sha256": signal["negative_canary"]["sha256"],
                    "reviewer": reviewer,
                    "source": source,
                }
                mappings.append(
                    {
                        "provider_item_id": item_id,
                        "central_owner": signal["central_owner"],
                        "negative_canary": receipt(
                            evidence,
                            f"signals/{index}/items/{item_index}.json",
                            item_canary,
                        ),
                    }
                )
                attested_item_canaries.append(item_canary)
            signal[mapping_field] = mappings
        if signal["id"] == "sca":
            for manifest_index, manifest in enumerate(signal["manifests"]):
                assert isinstance(manifest, dict)
                package = {
                    "name": f"dependency-{manifest_index}",
                    "version": "1.2.3",
                    "purl": f"pkg:generic/dependency-{manifest_index}@1.2.3",
                }
                manifest["resolved_graph"] = receipt(
                    evidence,
                    f"sca/{manifest_index}.graph.json",
                    {
                        "schema": "koios-ci/resolved-dependency-graph-v1",
                        "manifest": manifest["path"],
                        "profiles": manifest["profiles"],
                        "source": source,
                        "packages": [package],
                    },
                )
                manifest["sbom"] = receipt(
                    evidence,
                    f"sca/{manifest_index}.sbom.json",
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.5",
                        "version": 1,
                        "metadata": {
                            "component": {"name": REPOSITORY, "type": "application"},
                            "properties": [
                                {"name": "koios:manifest", "value": manifest["path"]},
                                {"name": "koios:profiles", "value": ",".join(manifest["profiles"])},
                            ],
                        },
                        "components": [{"type": "library", **package}],
                    },
                )
        if signal["id"] == "ai-review-readback":
            for readback_type in ("app", "subscription", "target"):
                signal[f"{readback_type}_readback"] = receipt(
                    evidence,
                    f"ai/{readback_type}.json",
                    {
                        "schema": f"koios-ci/deepsource-{readback_type}-readback-v1",
                        "repository": REPOSITORY,
                        "signal_id": "ai-review-readback",
                        "observed_at": OBSERVED_AT,
                        "state": {"enabled": False},
                        "reviewer": reviewer,
                        "source": source,
                    },
                )
    attested_item_canaries.sort(key=lambda item: (str(item["signal_id"]), str(item["provider_item_id"])))
    attestation_payload = {
        "schema": "koios-ci/deepsource-canary-execution-v1",
        "issuer": ATTESTATION_ISSUER,
        "key_id": ATTESTATION_KEY_ID,
        "repository": REPOSITORY,
        "source_sha": SOURCE_SHA,
        "source_config_digest": CONFIG_DIGEST,
        "issued_at": OBSERVED_AT,
        "canaries": attested_canaries,
        "item_canaries": attested_item_canaries,
    }
    payload_receipt = byte_receipt(
        evidence,
        "attestation/canary-execution.json",
        canonical_json_bytes(attestation_payload),
    )
    parity["canary_execution_attestation"] = byte_receipt(
        evidence,
        "attestation/envelope.json",
        canonical_json_bytes(
            {
                "schema": "koios-ci/deepsource-canary-attestation-v1",
                "algorithm": ATTESTATION_ALGORITHM,
                "key_id": ATTESTATION_KEY_ID,
                "public_key_sha256": ATTESTATION_PUBLIC_KEY_SHA256,
                "payload": payload_receipt,
                "signature": ATTESTATION_SIGNATURE,
            }
        ),
    )
    return parity


def rewrite_attested_item_canaries(
    fixture: Path,
    parity: dict[str, object],
    mutation: Callable[[list[dict[str, object]]], None],
) -> None:
    """Rewrite only the signed payload receipt while retaining the original signature."""
    evidence = fixture / "evidence"
    envelope_descriptor = parity["canary_execution_attestation"]
    assert isinstance(envelope_descriptor, dict)
    envelope_relative = str(envelope_descriptor["path"])
    envelope_path = evidence / envelope_relative
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    payload_descriptor = envelope["payload"]
    assert isinstance(payload_descriptor, dict)
    payload_relative = str(payload_descriptor["path"])
    payload_path = evidence / payload_relative
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    item_canaries = payload["item_canaries"]
    assert isinstance(item_canaries, list)
    mutation(item_canaries)
    envelope["payload"] = byte_receipt(
        evidence,
        payload_relative,
        canonical_json_bytes(payload),
    )
    parity["canary_execution_attestation"] = byte_receipt(
        evidence,
        envelope_relative,
        canonical_json_bytes(envelope),
    )


def test_v1_contract_validator_accepts_complete_synthetic_deepsource_parity(tmp_path: Path) -> None:
    """Catches an over-strict validator that cannot accept complete auditable replacement proof."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    path.write_text(json.dumps(materialize_complete_parity(fixture)), encoding="utf-8")

    validate_deepsource_fixture(fixture)


@pytest.mark.parametrize(
    "mutation",
    [
        "bare-boolean",
        "stale",
        "unauthenticated",
        "wrong-source",
        "wrong-provider",
        "invalid-reviewer",
        "contradictory-state",
    ],
)
def test_deepsource_hosted_preconditions_require_fresh_authenticated_semantic_receipts(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Catches a boolean or self-asserted hosted readback authorizing provider retirement."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)
    preconditions = parity["disposition_preconditions"]
    assert isinstance(preconditions, dict)
    if mutation == "bare-boolean":
        preconditions["live_ruleset_safe"] = True
    else:
        evidence = fixture / "evidence"
        descriptor = preconditions["live_ruleset_safe"]
        assert isinstance(descriptor, dict)
        relative = str(descriptor["path"])
        payload = json.loads((evidence / relative).read_text(encoding="utf-8"))
        if mutation == "stale":
            payload["captured_at"] = "2026-01-01T00:00:00Z"
        elif mutation == "unauthenticated":
            payload["authentication"]["authenticated"] = False
        elif mutation == "wrong-source":
            payload["source"]["repository"] = "koios-ai/other"
        elif mutation == "wrong-provider":
            payload["provider"]["app"]["id"] = 1
        elif mutation == "invalid-reviewer":
            payload["reviewer"]["id"] = 0
        else:
            payload["state"]["deepsource_required"] = False
        preconditions["live_ruleset_safe"] = receipt(evidence, relative, payload)
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    path.write_text(json.dumps(parity), encoding="utf-8")

    expected = r"readback|receipt|schema|timestamp|source|provider|reviewer|contradict"
    with pytest.raises((ValueError, jsonschema.ValidationError), match=expected):
        validate_deepsource_fixture(fixture)


def test_deepsource_retention_does_not_require_duplicate_replacement_claims(tmp_path: Path) -> None:
    """Catches replacement evidence being required even when an uncovered signal remains retained."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)
    static = next(item for item in parity["signals"] if item["id"] == "python-static-quality")
    sca = next(item for item in parity["signals"] if item["id"] == "sca")
    static.pop("rule_mappings")
    sca.pop("capability_mappings")
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    path.write_text(json.dumps(parity), encoding="utf-8")

    validate_deepsource_fixture(fixture)


def test_v1_contract_validator_rejects_copied_expected_bytes_without_authenticated_provenance(
    tmp_path: Path,
) -> None:
    """Catches copied platform-expected output bytes being mistaken for proof that an owner command ran."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)
    parity.pop("canary_execution_attestation")
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    path.write_text(json.dumps(parity), encoding="utf-8")

    with pytest.raises(ValueError, match=r"canary_execution_attestation|authenticated execution attestation"):
        validate_deepsource_fixture(fixture)


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown-key-id",
        "unknown-algorithm",
        "wrong-public-key-digest",
        "unknown-envelope-field",
        "noncanonical-envelope",
        "duplicate-envelope-key",
        "invalid-signature",
        "noncanonical-payload",
        "duplicate-payload-key",
        "stale-attestation",
        "future-attestation",
        "repository-mismatch",
        "config-mismatch",
        "version-mismatch",
        "fixture-mismatch",
        "output-mismatch",
    ],
)
def test_v1_contract_validator_rejects_untrusted_or_malleable_execution_attestations(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Catches unsigned, ambiguously encoded, stale, or semantically detached canary provenance."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)
    evidence = fixture / "evidence"
    attestation = parity["canary_execution_attestation"]
    assert isinstance(attestation, dict)
    envelope_path = evidence / str(attestation["path"])
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    payload_receipt = envelope["payload"]
    payload_path = evidence / str(payload_receipt["path"])
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    payload_bytes: bytes | None = None
    envelope_bytes: bytes | None = None
    if mutation == "unknown-key-id":
        envelope["key_id"] = "unknown-key"
    elif mutation == "unknown-algorithm":
        envelope["algorithm"] = "unknown"
    elif mutation == "wrong-public-key-digest":
        envelope["public_key_sha256"] = "0" * 64
    elif mutation == "unknown-envelope-field":
        envelope["untrusted"] = True
    elif mutation == "noncanonical-envelope":
        envelope_bytes = json.dumps(envelope, indent=2).encode()
    elif mutation == "duplicate-envelope-key":
        envelope_bytes = canonical_json_bytes(envelope)[:-1] + b',"key_id":"duplicate"}'
    elif mutation == "invalid-signature":
        envelope["signature"] = "AAAA"
    elif mutation == "noncanonical-payload":
        payload_bytes = json.dumps(payload, indent=2).encode()
    elif mutation == "duplicate-payload-key":
        payload_bytes = canonical_json_bytes(payload)[:-1] + b',"issuer":"duplicate"}'
    elif mutation == "stale-attestation":
        payload["issued_at"] = "2026-01-01T00:00:00Z"
    elif mutation == "future-attestation":
        payload["issued_at"] = "2026-07-28T00:00:00Z"
    elif mutation == "repository-mismatch":
        payload["repository"] = "koios-ai/other"
    elif mutation == "config-mismatch":
        payload["source_config_digest"] = "0" * 64
    elif mutation == "version-mismatch":
        payload["canaries"][0]["owner"]["version"] = "mypy==0.0.0"
    elif mutation == "fixture-mismatch":
        payload["canaries"][0]["fixture"]["sha256"] = "0" * 64
    else:
        payload["canaries"][0]["stdout"]["sha256"] = "0" * 64
    if mutation not in {
        "unknown-key-id",
        "unknown-algorithm",
        "wrong-public-key-digest",
        "unknown-envelope-field",
        "noncanonical-envelope",
        "duplicate-envelope-key",
        "invalid-signature",
    }:
        if payload_bytes is None:
            payload_bytes = canonical_json_bytes(payload)
        envelope["payload"] = byte_receipt(
            evidence,
            str(payload_receipt["path"]),
            payload_bytes,
        )
    parity["canary_execution_attestation"] = byte_receipt(
        evidence,
        str(attestation["path"]),
        envelope_bytes if envelope_bytes is not None else canonical_json_bytes(envelope),
    )
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    path.write_text(json.dumps(parity), encoding="utf-8")

    with pytest.raises(ValueError, match=r"attestation|signature|canonical|duplicate"):
        validate_deepsource_fixture(fixture)


def test_deepsource_schema_accepts_blocked_template_and_requires_complete_evidence(tmp_path: Path) -> None:
    """Catches schema/validator drift that rejects null blockers or permits evidence-free completion."""
    fixture = copy_contract_fixture(tmp_path)
    schema = json.loads((fixture / "contract/deepsource-parity-v1.schema.json").read_text(encoding="utf-8"))
    blocked = json.loads(
        (fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(schema).validate(blocked)

    complete = materialize_complete_parity(fixture)
    complete.pop("source_config_digest")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(complete)


@pytest.mark.parametrize("mutation", ["wrong-app", "missing-check", "unexpected-check"])
def test_v1_contract_validator_requires_exact_deepsource_app_and_check_inventory(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Catches a generic DeepSource prefix or one successful check standing in for the closed App inventory."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)
    evidence = fixture / "evidence"
    inventory = parity["hosted_inventory_artifact"]
    assert isinstance(inventory, dict)
    payload = json.loads((evidence / str(inventory["path"])).read_text(encoding="utf-8"))
    if mutation == "wrong-app":
        payload["provider_app"]["id"] = 1
    elif mutation == "missing-check":
        payload["expected_checks"].pop()
    else:
        payload["expected_checks"].append({"name": "DeepSource: arbitrary", "state": "success", "app": DEEPSOURCE_APP})
    parity["hosted_inventory_artifact"] = receipt(evidence, str(inventory["path"]), payload)
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    path.write_text(json.dumps(parity), encoding="utf-8")

    with pytest.raises(ValueError, match=r"App|check inventory"):
        validate_deepsource_fixture(fixture)


@pytest.mark.parametrize(
    "mutation",
    ["missing-maintenance", "wrong-constraints", "missing-conda-surface", "unbound-present-conda"],
)
def test_v1_contract_validator_requires_closed_python_sca_manifest_surfaces(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Catches incomplete maintenance/profile constraints or implicit Conda discovery in SCA parity."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)
    sca = next(item for item in parity["signals"] if item["id"] == "sca")
    if mutation == "missing-maintenance":
        sca["manifests"] = [
            manifest for manifest in sca["manifests"] if manifest["path"] != "requirements-maintenance.txt"
        ]
    elif mutation == "wrong-constraints":
        sca["canonical_constraints"] = "constraints-dev.txt"
    elif mutation == "missing-conda-surface":
        sca["optional_conda_surfaces"].pop()
    else:
        sca["optional_conda_surfaces"][0]["present"] = True
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    path.write_text(json.dumps(parity), encoding="utf-8")

    with pytest.raises(ValueError, match=r"SCA|Conda|conda|constraints|maintenance"):
        validate_deepsource_fixture(fixture)


@pytest.mark.parametrize(
    ("signal_id", "mapping_field", "mutation"),
    [
        ("python-static-quality", "rule_mappings", "missing"),
        ("python-static-quality", "rule_mappings", "duplicate"),
        ("python-static-quality", "rule_mappings", "wrong-owner"),
        ("sca", "capability_mappings", "missing"),
        ("sca", "capability_mappings", "duplicate"),
        ("sca", "capability_mappings", "wrong-owner"),
    ],
)
def test_deepsource_replace_requires_exhaustive_unique_executed_item_mappings(
    tmp_path: Path,
    signal_id: str,
    mapping_field: str,
    mutation: str,
) -> None:
    """Catches broad replacement after omitting or duplicating a hosted rule/capability proof."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)
    signal = next(item for item in parity["signals"] if item["id"] == signal_id)
    signal["outcome"] = "replace-proven-duplicate"
    mappings = signal[mapping_field]
    assert isinstance(mappings, list)
    if mutation == "missing":
        mappings.pop()
    elif mutation == "duplicate":
        mappings[-1] = json.loads(json.dumps(mappings[0]))
    else:
        mappings[0]["central_owner"] = "unrelated-owner"
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    path.write_text(json.dumps(parity), encoding="utf-8")

    with pytest.raises(ValueError, match=r"rule|capabilit|mapping|owner|replacement"):
        validate_deepsource_fixture(fixture)


def test_deepsource_replace_rejects_untyped_or_duplicate_hosted_rule_ids(tmp_path: Path) -> None:
    """Catches a meaningless non-empty rule list satisfying static-analysis replacement."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)
    signal = next(item for item in parity["signals"] if item["id"] == "python-static-quality")
    signal["outcome"] = "replace-proven-duplicate"
    signal["rule_ids"] = [None, None]
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    path.write_text(json.dumps(parity), encoding="utf-8")

    with pytest.raises((ValueError, jsonschema.ValidationError), match=r"rule|mapping|inventory"):
        validate_deepsource_fixture(fixture)


def test_deepsource_replace_rejects_rehashed_item_canary_outside_signed_attestation(tmp_path: Path) -> None:
    """Catches a semantically valid per-item receipt being rewritten after the signed execution."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)
    signal = next(item for item in parity["signals"] if item["id"] == "python-static-quality")
    signal["outcome"] = "replace-proven-duplicate"
    mapping = signal["rule_mappings"][0]
    descriptor = mapping["negative_canary"]
    evidence = fixture / "evidence"
    relative = str(descriptor["path"])
    payload = json.loads((evidence / relative).read_text(encoding="utf-8"))
    payload["executed_at"] = "2026-07-27T12:01:00Z"
    mapping["negative_canary"] = receipt(evidence, relative, payload)
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    path.write_text(json.dumps(parity), encoding="utf-8")

    with pytest.raises(ValueError, match=r"attest|signed"):
        validate_deepsource_fixture(fixture)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "wrong-signal", "extra"])
def test_deepsource_signed_item_canary_set_exactly_matches_hosted_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    """Catches signed static-rule/SCA canaries omitting, duplicating, or inventing hosted items."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)

    def mutate(item_canaries: list[dict[str, object]]) -> None:
        if mutation == "missing":
            item_canaries.pop()
        elif mutation == "duplicate":
            item_canaries.append(json.loads(json.dumps(item_canaries[0])))
        elif mutation == "wrong-signal":
            item_canaries[0]["signal_id"] = "ruff-transformer"
        else:
            extra = json.loads(json.dumps(item_canaries[0]))
            extra["provider_item_id"] = "provider-only-extra-rule"
            item_canaries.append(extra)

    rewrite_attested_item_canaries(fixture, parity, mutate)
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    path.write_text(json.dumps(parity), encoding="utf-8")
    module = load_validator()
    monkeypatch.setattr(module, "verify_rsa_pkcs1v15_sha256", lambda *_args: True)

    with pytest.raises(ValueError, match=r"item.*(?:inventory|duplicat|signed)"):
        module.validate_deepsource_parity(
            fixture,
            as_of=module.dt.datetime(2026, 7, 27, 13, tzinfo=module.dt.UTC),
        )


@pytest.mark.parametrize(
    "signal_id",
    [
        "python-static-quality",
        "ruff-transformer",
        "sca",
        "secrets",
        "docker-compose-config",
        "adapter-integrity",
        "coverage",
    ],
)
def test_v1_contract_validator_accepts_evidence_supported_non_ai_deepsource_dispositions(
    tmp_path: Path,
    signal_id: str,
) -> None:
    """Catches policy hardcoding retain or replace after complete signal-level proof exists."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)
    signal = next(item for item in parity["signals"] if item["id"] == signal_id)
    signal["outcome"] = (
        "replace-proven-duplicate"
        if signal["outcome"] == "retain-unique-defense-in-depth"
        else "retain-unique-defense-in-depth"
    )
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    path.write_text(json.dumps(parity), encoding="utf-8")

    validate_deepsource_fixture(fixture)


@pytest.mark.parametrize("outcome", ["retain-unique-defense-in-depth", "replace-proven-duplicate"])
def test_v1_contract_validator_never_reclassifies_usage_priced_deepsource_ai(
    tmp_path: Path,
    outcome: str,
) -> None:
    """Catches complete deterministic evidence being misused to authorize metered AI Review."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)
    next(item for item in parity["signals"] if item["id"] == "ai-review-readback")["outcome"] = outcome
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    path.write_text(json.dumps(parity), encoding="utf-8")

    with pytest.raises((ValueError, jsonschema.ValidationError), match=r"outcome|disable-usage-based-ai"):
        validate_deepsource_fixture(fixture)


@pytest.mark.parametrize("mutation", ["missing-adapter", "missing-secret-trigger-gap"])
def test_v1_contract_validator_requires_adapter_and_secret_trigger_gap_evidence(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Catches adapter mapping or the known docs/config provider trigger gap disappearing from disposition."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)
    if mutation == "missing-adapter":
        parity["signals"] = [signal for signal in parity["signals"] if signal["id"] != "adapter-integrity"]
    else:
        secrets = next(signal for signal in parity["signals"] if signal["id"] == "secrets")
        secrets["provider_trigger_gaps"].pop()
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    path.write_text(json.dumps(parity), encoding="utf-8")

    with pytest.raises(ValueError, match=r"adapter|signals|trigger|provider_trigger_gaps"):
        validate_deepsource_fixture(fixture)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("empty-receipt", "semantic"),
        ("wrong-signal", "signal_id"),
        ("wrong-exit", "actual_exit"),
        ("wrong-version", "version"),
        ("wrong-config", "config_digest"),
        ("boolean-exit", "actual_exit"),
        ("future-timestamp", "executed_at"),
    ],
)
def test_v1_contract_validator_rejects_semantically_invalid_canary_receipts(
    tmp_path: Path, mutation: str, expected: str
) -> None:
    """Catches hash-valid receipts whose contents do not prove the claimed canary."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)
    signals = parity["signals"]
    assert isinstance(signals, list)
    signal = signals[0]
    assert isinstance(signal, dict)
    canary = signal["negative_canary"]
    assert isinstance(canary, dict)
    evidence = fixture / "evidence"
    path = evidence / str(canary["path"])
    payload = json.loads(path.read_text(encoding="utf-8"))
    if mutation == "empty-receipt":
        payload = {}
    elif mutation == "wrong-signal":
        payload["signal_id"] = "secrets"
    elif mutation == "wrong-exit":
        payload["actual_exit"] = 0
    elif mutation == "wrong-version":
        payload["owner"]["version"] = "mypy==0.0.0"
    elif mutation == "wrong-config":
        payload["owner"]["config_digest"] = "0" * 64
    elif mutation == "boolean-exit":
        payload["expected_exit"] = False
        payload["actual_exit"] = False
    else:
        payload["executed_at"] = "2026-07-28T12:00:00Z"
    signal["negative_canary"] = receipt(evidence, str(canary["path"]), payload)
    parity_path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    parity_path.write_text(json.dumps(parity), encoding="utf-8")

    with pytest.raises(ValueError, match=expected):
        validate_deepsource_fixture(fixture)


def test_v1_contract_validator_rejects_contradictory_ai_and_readback_states(tmp_path: Path) -> None:
    """Catches AI Review being called disabled while a field or provider readback says enabled."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)
    signals = parity["signals"]
    assert isinstance(signals, list)
    ai = next(item for item in signals if item["id"] == "ai-review-readback")
    assert isinstance(ai, dict)
    for contradiction in ("field", "payload"):
        candidate = json.loads(json.dumps(parity))
        candidate_ai = next(item for item in candidate["signals"] if item["id"] == "ai-review-readback")
        if contradiction == "field":
            candidate_ai["enabled_readback"] = True
        else:
            app = candidate_ai["app_readback"]
            app_path = fixture / "evidence" / app["path"]
            app_payload = json.loads(app_path.read_text(encoding="utf-8"))
            app_payload["state"]["enabled"] = True
            candidate_ai["app_readback"] = receipt(fixture / "evidence", app["path"], app_payload)
        parity_path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
        parity_path.write_text(json.dumps(candidate), encoding="utf-8")
        with pytest.raises(ValueError, match="AI Review"):
            validate_deepsource_fixture(fixture)


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong-exit-code",
        "coordinated-exit-127",
        "changed-output-bytes",
        "swapped-output-receipts",
        "copied-output-receipt",
        "aliased-copied-output-receipt",
        "coordinated-output-receipt",
        "self-declared-output-digests",
    ],
)
def test_v1_contract_validator_rejects_untrusted_canary_output_evidence(tmp_path: Path, mutation: str) -> None:
    """Catches unbacked, swapped, copied, or fabricated canary output evidence."""
    fixture = copy_contract_fixture(tmp_path)
    parity = materialize_complete_parity(fixture)
    signal = next(item for item in parity["signals"] if item["id"] == "sca")
    negative = signal["negative_canary"]
    evidence = fixture / "evidence"
    payload = json.loads((evidence / negative["path"]).read_text(encoding="utf-8"))
    if mutation == "wrong-exit-code":
        payload["actual_exit"] = 127
    elif mutation == "coordinated-exit-127":
        payload["expected_exit"] = 127
        payload["actual_exit"] = 127
    elif mutation == "changed-output-bytes":
        (evidence / payload["stderr"]["path"]).write_bytes(b"changed after capture")
    elif mutation == "swapped-output-receipts":
        payload["stdout"], payload["stderr"] = payload["stderr"], payload["stdout"]
    elif mutation in {"copied-output-receipt", "aliased-copied-output-receipt"}:
        positive = signal["positive_canary"]
        positive_payload = json.loads((evidence / positive["path"]).read_text(encoding="utf-8"))
        payload["stderr"] = positive_payload["stderr"]
        if mutation == "aliased-copied-output-receipt":
            original = Path(payload["stderr"]["path"])
            payload["stderr"]["path"] = str(original.parent / ".." / original.parent.name / original.name)
    elif mutation == "coordinated-output-receipt":
        payload["stderr"] = byte_receipt(
            evidence,
            payload["stderr"]["path"],
            b"fabricated but internally hash-consistent",
        )
    else:
        stdout = payload.pop("stdout")
        stderr = payload.pop("stderr")
        payload["stdout_sha256"] = stdout["sha256"]
        payload["stderr_sha256"] = stderr["sha256"]
        payload["expected_diagnostic_sha256"] = stderr["sha256"]
        payload["actual_diagnostic_sha256"] = stderr["sha256"]
    signal["negative_canary"] = receipt(evidence, negative["path"], payload)
    parity_path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    parity_path.write_text(json.dumps(parity), encoding="utf-8")

    with pytest.raises(ValueError, match=r"actual_exit|output|receipt|semantic"):
        validate_deepsource_fixture(fixture)


def test_v1_contract_validator_rejects_missing_deepsource_negative_canary(tmp_path: Path) -> None:
    """Catches removal of a failing canary from a signal claimed as proven."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    parity_map = materialize_complete_parity(fixture)
    signals = parity_map["signals"]
    assert isinstance(signals, list)
    signals[2].pop("negative_canary")
    path.write_text(json.dumps(parity_map), encoding="utf-8")

    with pytest.raises(ValueError, match="negative_canary"):
        validate_deepsource_fixture(fixture)


def test_v1_contract_validator_rejects_complete_parity_without_evidence_root(tmp_path: Path) -> None:
    """Catches a claimed hosted parity proof made entirely of unbound strings."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    parity = materialize_complete_parity(fixture)
    parity.pop("evidence_root")
    path.write_text(json.dumps(parity), encoding="utf-8")

    with pytest.raises(ValueError, match="evidence_root"):
        validate_deepsource_fixture(fixture)


def test_v1_contract_validator_rejects_bad_evidence_receipts(tmp_path: Path) -> None:
    """Catches missing, escaping, altered, oversized, stale, and invented AI receipts."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / "templates/consumer/.github/ci-platform-deepsource-parity.json"
    parity = materialize_complete_parity(fixture)
    signals = parity["signals"]
    assert isinstance(signals, list)
    for expected in ("missing", "traversal", "hash", "bytes", "readback"):
        candidate = json.loads(json.dumps(parity))
        if expected == "readback":
            candidate_signals = candidate["signals"]
            assert isinstance(candidate_signals, list)
            next(item for item in candidate_signals if item["id"] == "ai-review-readback").pop("app_readback")
        else:
            inventory = candidate["hosted_inventory_artifact"]
            assert isinstance(inventory, dict)
            if expected == "missing":
                inventory["path"] = "missing.json"
            if expected == "traversal":
                inventory["path"] = "../escape"
            if expected == "hash":
                inventory["sha256"] = "0" * 64
            if expected == "bytes":
                inventory["bytes"] = 1
        path.write_text(json.dumps(candidate), encoding="utf-8")
        with pytest.raises(ValueError):
            validate_deepsource_fixture(fixture)
    path.write_text(json.dumps(parity), encoding="utf-8")
    parity["hosted_inventory_observed_at"] = "2026-01-01T00:00:00Z"
    path.write_text(json.dumps(parity), encoding="utf-8")
    with pytest.raises(ValueError):
        validate_deepsource_fixture(fixture)


def test_merge_gate_v1_has_only_ruleset_events_and_no_provider_pass_synthesis() -> None:
    """Catches reintroducing filtered triggers or pretending draft/queue AI evidence passed."""
    workflow_path = ROOT / ".github/workflows/merge-gate-v1.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    raw = workflow_path.read_text(encoding="utf-8")

    assert workflow["name"] == "Koios CI / merge gate"
    assert workflow[True] == {"pull_request": None, "merge_group": None}
    assert "provider PASS" not in raw
    assert "merge_gate_policy.py" in raw


def test_merge_gate_v1_binds_one_profile_and_keeps_platform_code_separate_from_target_code() -> None:
    """Catches an untrusted PR selecting a weaker matrix lane or replacing platform validation."""
    workflow_path = ROOT / ".github/workflows/merge-gate-v1.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]

    assert workflow["env"]["CI_PLATFORM_PROFILE"] == "baseline"
    assert "strategy" not in jobs["deterministic"]
    assert "fast-scope" in jobs["coverage"]["needs"]
    for job_id in ("deterministic", "security", "coverage"):
        checkout = next(step for step in jobs[job_id]["steps"] if step.get("with", {}).get("path") == "platform")
        assert checkout["with"] == {
            "repository": "${{ job.workflow_repository }}",
            "ref": "${{ job.workflow_sha }}",
            "path": "platform",
            "persist-credentials": False,
        }
    raw = workflow_path.read_text(encoding="utf-8")
    assert "job.workflow_file_path" in raw
    assert "job.workflow_ref" in raw
    assert "--workflow-sha '${{ job.workflow_sha }}'" in raw
    assert "compileall" not in raw
    assert "|| true" not in raw
    assert "profile_runner.py --execute" in raw


def test_merge_gate_v1_runs_trusted_policy_and_closed_native_runner_against_exact_target() -> None:
    """Catches Node/PowerShell remaining plan-only or executing platform code from the untrusted target."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/merge-gate-v1.yml").read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    deterministic = jobs["deterministic"]
    target_checkout = next(step for step in deterministic["steps"] if step.get("with", {}).get("path") == "target")
    assert target_checkout["with"] == {
        "ref": "${{ needs.fast-scope.outputs.head_sha }}",
        "fetch-depth": 0,
        "path": "target",
        "persist-credentials": False,
    }
    assert not any(step.get("name") == "Set up pinned Node runtime" for step in deterministic["steps"])
    profile_step = next(step for step in deterministic["steps"] if step.get("name") == "Run deterministic profile")
    assert "if" not in profile_step
    assert "platform/scripts/profile_runner.py --execute" in profile_step["run"]
    assert "--root target" in profile_step["run"]
    assert "--lane deterministic" in profile_step["run"]
    assert "pytest" not in profile_step["run"]
    assert "bandit" not in profile_step["run"]
    runtime = jobs["runtime-evidence"]
    runtime_step = next(
        step
        for step in runtime["steps"]
        if step.get("name") == "Run target only inside constrained digest-pinned containers"
    )
    assert "run_isolated_runtime.py" in runtime_step["run"]
    assert "/var/run/docker.sock" not in json.dumps(runtime)
    verifier = next(
        step
        for step in jobs["coverage"]["steps"]
        if step.get("name") == "Verify bounded provenance and coverage in a fresh job"
    )
    assert "verify_runtime_evidence.py" in verifier["run"]
    assert any(
        step.get("name") == "Fail closed pending unforgeable target-supervisor hosted canary"
        for step in jobs["coverage"]["steps"]
    )


def test_merge_gate_v1_is_the_only_source_bound_ruleset_candidate() -> None:
    """Catches profile routing relying on runtime properties or an extra competing required gate."""
    candidates: list[str] = []
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        events = workflow.get(True, workflow.get("on", {})) if isinstance(workflow, dict) else {}
        if (
            isinstance(events, dict)
            and {"pull_request", "merge_group"} <= set(events)
            and workflow.get("name") == "Koios CI / merge gate"
        ):
            candidates.append(path.name)
    assert sorted(candidates) == sorted(PROFILE_WORKFLOWS.values())
    for profile, workflow_name in PROFILE_WORKFLOWS.items():
        workflow = yaml.safe_load((ROOT / ".github/workflows" / workflow_name).read_text(encoding="utf-8"))
        assert workflow["name"] == "Koios CI / merge gate"
        assert workflow["env"] == {"CI_PLATFORM_PROFILE": profile}
        assert f"merge-gate-v1-{profile}-" in workflow["concurrency"]["group"]
        assert "env.CI_PLATFORM_PROFILE" not in workflow["concurrency"]["group"]
        assert workflow["jobs"]["merge"]["name"] == consumer_terminal_job_name(profile)
    legacy = yaml.safe_load((ROOT / ".github/workflows/required.yml").read_text(encoding="utf-8"))
    assert legacy["name"] == "LEGACY / inactive required integrity"
    assert legacy.get(True, legacy.get("on")) == {"workflow_dispatch": None}
    assert legacy["jobs"]["required"]["name"] != "CI / required"


def test_profile_workflows_are_deterministically_generated_and_ruleset_targeted_only() -> None:
    """Catches generated profile drift or claims that custom properties become workflow inputs."""
    generator = ROOT / "scripts/generate_merge_gate_profiles.py"
    result = subprocess.run(
        [sys.executable, str(generator), "--root", str(ROOT), "--check"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    contract = json.loads((ROOT / "contract/v1.json").read_text(encoding="utf-8"))["x-merge-gate-v1"]
    assert contract["profile_workflows"] == {
        profile: f".github/workflows/{workflow}" for profile, workflow in PROFILE_WORKFLOWS.items()
    }
    assert contract["profile_selection"] == {
        "authority": "separate-organization-rulesets",
        "target_filter_template": "props.ci_profile:<profile>",
        "assignment_authority": "explicit-user-specified-only",
        "runtime_custom_property_input": False,
        "one_active_required_workflow_per_repository": True,
        "hosted_readback_required": True,
    }
    assert contract["source_repository_policy"] == {
        "repository": SOURCE_REPOSITORY,
        "profile_workflow_jobs": "disabled",
        "consumer_required_context": "CI / required",
        "source_disabled_contexts": SOURCE_DISABLED_JOB_NAMES,
        "internal_workflow": ".github/workflows/continuous-validation.yml",
        "internal_job": "Koios CI / source validation",
        "internal_triggers": ["pull_request", "merge_group", "push-main", "schedule"],
    }


def test_all_profile_jobs_are_source_guarded_and_only_consumers_publish_ci_required() -> None:
    """Catches any generated profile self-triggering in the platform source repository."""
    for profile, workflow_name in PROFILE_WORKFLOWS.items():
        workflow = yaml.safe_load((ROOT / ".github/workflows" / workflow_name).read_text(encoding="utf-8"))
        for job_id, job in workflow["jobs"].items():
            condition = str(job.get("if", ""))
            assert condition == SOURCE_REPOSITORY_GUARD or condition.startswith(f"{SOURCE_REPOSITORY_GUARD} && "), (
                f"{workflow_name}:{job_id} is not source-repository guarded"
            )
            assert "||" not in condition, f"{workflow_name}:{job_id} can bypass the source-repository guard"
        assert workflow["jobs"]["merge"]["name"] == consumer_terminal_job_name(profile)
        assert workflow["jobs"]["merge"]["if"] == f"{SOURCE_REPOSITORY_GUARD} && always()"


def test_validator_rejects_a_missing_source_repository_job_guard(tmp_path: Path) -> None:
    """Catches generator or hand-edit drift that lets one profile job run in the source repository."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / ".github/workflows/merge-gate-v1.yml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            f"    if: {SOURCE_REPOSITORY_GUARD}\n",
            "",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="source repository guard"):
        load_validator().validate_workflow(fixture)


SOURCE_TRIGGER_CASES = [
    ("pull_request", None),
    ("merge_group", None),
    ("push", {"branches": ["main"]}),
    ("schedule", [{"cron": "11 4 * * *"}]),
]


def write_auxiliary_source_workflow(
    fixture: Path,
    *,
    trigger: str,
    event_value: object,
    condition: str | None,
) -> None:
    job: dict[str, object] = {
        "name": "Duplicate source validation",
        "runs-on": "ubuntu-24.04",
        "steps": [{"run": "echo duplicate substantive source gate"}],
    }
    if condition is not None:
        job["if"] = condition
    workflow = {
        "name": "Duplicate source validation",
        "on": {trigger: event_value},
        "permissions": {"contents": "read"},
        "jobs": {"duplicate-source-gate": job},
    }
    path = fixture / ".github/workflows/duplicate-source-validation.yml"
    path.write_text(yaml.safe_dump(workflow, sort_keys=False), encoding="utf-8")


@pytest.mark.parametrize(("trigger", "event_value"), SOURCE_TRIGGER_CASES)
def test_validator_rejects_a_second_substantive_source_gate_for_every_source_trigger(
    tmp_path: Path,
    trigger: str,
    event_value: object,
) -> None:
    """Catches a second internal source gate hiding on any supported source event."""
    fixture = copy_contract_fixture(tmp_path)
    write_auxiliary_source_workflow(
        fixture,
        trigger=trigger,
        event_value=event_value,
        condition=None,
    )

    with pytest.raises(ValueError, match="sole source repository"):
        load_validator().validate_workflow(fixture)


@pytest.mark.parametrize(("trigger", "event_value"), SOURCE_TRIGGER_CASES)
@pytest.mark.parametrize(
    "condition",
    [
        f"{SOURCE_REPOSITORY_GUARD} || true",
        f"{SOURCE_REPOSITORY_GUARD} && always() || true",
        f"true || {SOURCE_REPOSITORY_GUARD}",
        f"${{{{ {SOURCE_REPOSITORY_GUARD} || true }}}}",
    ],
)
def test_validator_rejects_semantic_source_guard_bypasses_on_every_source_trigger(
    tmp_path: Path,
    trigger: str,
    event_value: object,
    condition: str,
) -> None:
    """Catches substring matching accepting an OR-bypass as source suppression."""
    fixture = copy_contract_fixture(tmp_path)
    write_auxiliary_source_workflow(
        fixture,
        trigger=trigger,
        event_value=event_value,
        condition=condition,
    )

    with pytest.raises(ValueError, match="sole source repository"):
        load_validator().validate_workflow(fixture)


@pytest.mark.parametrize(("trigger", "event_value"), SOURCE_TRIGGER_CASES)
@pytest.mark.parametrize(
    "condition",
    [SOURCE_REPOSITORY_GUARD, f"{SOURCE_REPOSITORY_GUARD} && always()"],
)
def test_validator_accepts_exact_source_suppression_on_every_source_trigger(
    tmp_path: Path,
    trigger: str,
    event_value: object,
    condition: str,
) -> None:
    """Preserves exact source suppression for non-internal source-triggered workflows."""
    fixture = copy_contract_fixture(tmp_path)
    write_auxiliary_source_workflow(
        fixture,
        trigger=trigger,
        event_value=event_value,
        condition=condition,
    )

    load_validator().validate_workflow(fixture)


@pytest.mark.parametrize("events", ["pull_request", ["merge_group"], ["push"]])
def test_validator_rejects_compact_duplicate_source_trigger_syntax(
    tmp_path: Path,
    events: object,
) -> None:
    """Catches scalar or list event syntax bypassing the sole-source-gate scan."""
    fixture = copy_contract_fixture(tmp_path)
    workflow = {
        "name": "Duplicate compact source validation",
        "on": events,
        "permissions": {"contents": "read"},
        "jobs": {
            "duplicate-source-gate": {
                "runs-on": "ubuntu-24.04",
                "steps": [{"run": "echo duplicate substantive source gate"}],
            }
        },
    }
    path = fixture / ".github/workflows/duplicate-compact-source-validation.yml"
    path.write_text(yaml.safe_dump(workflow, sort_keys=False), encoding="utf-8")

    with pytest.raises(ValueError, match="sole source repository"):
        load_validator().validate_workflow(fixture)


def test_active_profile_terminals_are_the_only_ci_required_publishers(tmp_path: Path) -> None:
    """Catches the inactive manual workflow retaining ownership of the required CI context."""
    expected_workflows = {profile: f".github/workflows/{workflow}" for profile, workflow in PROFILE_WORKFLOWS.items()}
    contract = json.loads((ROOT / "contract/v1.json").read_text(encoding="utf-8"))

    assert contract["x-context-owners"]["CI / required"] == {
        "publisher": "organization-required-workflow-terminal",
        "profile_workflows": expected_workflows,
        "job": "merge",
        "required_job": "CI / required",
        "target": "event-head",
        "trusted_metadata_only": False,
    }

    fixture = copy_contract_fixture(tmp_path)
    path = fixture / "contract/v1.json"
    mutated = json.loads(path.read_text(encoding="utf-8"))
    mutated["x-context-owners"]["CI / required"] = {
        "publisher": "workflow",
        "workflow": ".github/workflows/required.yml",
        "target": "event-head",
        "trusted_metadata_only": False,
    }
    path.write_text(json.dumps(mutated), encoding="utf-8")

    with pytest.raises(ValueError, match=r"CI / required|context owner|publisher"):
        load_validator().validate_profile_contract(fixture)


def test_final_candidate_blocks_false_and_allows_true_without_inverting_admission() -> None:
    """Catches admitted=true failing or heavy jobs running after false final admission."""
    for workflow_name in PROFILE_WORKFLOWS.values():
        workflow = yaml.safe_load((ROOT / ".github/workflows" / workflow_name).read_text(encoding="utf-8"))
        final = workflow["jobs"]["final-candidate"]
        step = final["steps"][0]
        assert "if [[ '${{ needs.fast-scope.outputs.admitted }}' != 'true' ]]" in step["run"]
        assert "exit 1" in step["run"]
        for job_id in ("deterministic", "security", "coverage", "coderabbit-evidence", "codex-evidence"):
            job = workflow["jobs"][job_id]
            assert "final-candidate" in job["needs"]
            assert "needs.final-candidate.result == 'success'" in job["if"]
            assert "needs.final-candidate.outputs.admitted == 'true'" in job["if"]


def test_non_final_candidates_cannot_launch_profile_commands() -> None:
    """Catches draft/initial runs escaping the bounded deterministic-plus-secret fast lane."""
    for workflow_name in PROFILE_WORKFLOWS.values():
        workflow = yaml.safe_load((ROOT / ".github/workflows" / workflow_name).read_text(encoding="utf-8"))
        jobs = workflow["jobs"]
        scope_commands = "\n".join(str(step.get("run", "")) for step in jobs["fast-scope"]["steps"])
        assert "profile_runner.py" not in scope_commands
        assert "pip install" not in scope_commands
        fast = jobs["fast-deterministic"]
        fast_commands = "\n".join(str(step.get("run", "")) for step in fast["steps"])
        assert fast["needs"] == "fast-scope"
        assert fast["if"] == f"{SOURCE_REPOSITORY_GUARD} && needs.fast-scope.result == 'success'"
        assert "profile_runner.py --execute" in fast_commands
        assert "--lane deterministic" in fast_commands
        assert "secret_scan.py" in fast_commands
        assert "platform/requirements-dev.txt" in fast_commands
        assert "target/requirements" not in fast_commands
        assert "run_isolated_runtime.py" not in fast_commands
        assert "run_test_policy.py" not in fast_commands
        assert "bandit" not in fast_commands
        assert "pip-audit" not in fast_commands
        for job_id in (
            "deterministic",
            "security",
            "runtime-evidence",
            "coverage",
            "coderabbit-evidence",
            "codex-evidence",
            "findings-resolved",
        ):
            job = workflow["jobs"][job_id]
            assert "final-candidate" in job["needs"]
            assert "needs.final-candidate.result == 'success'" in job["if"]
            assert "needs.final-candidate.outputs.admitted == 'true'" in job["if"]


def test_v1_contract_validator_rejects_heavy_work_smuggled_into_the_fast_lane(tmp_path: Path) -> None:
    """Catches a non-final run acquiring a heavyweight or target-dependency command."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / ".github/workflows/merge-gate-v1.yml"
    raw = path.read_text(encoding="utf-8")
    marker = (
        'echo "Affected-test execution remains non-authoritative until candidate code '
        'cannot forge completion evidence." >&2'
    )
    raw = raw.replace(
        marker,
        f"python -m bandit -r target\n          {marker}",
    )
    path.write_text(raw, encoding="utf-8")

    with pytest.raises(ValueError, match="fast deterministic lane"):
        load_validator().validate_workflow(fixture)


@pytest.mark.parametrize("mutation", ["missing-result", "weak-result", "inverted-admission"])
def test_v1_contract_validator_requires_closed_terminal_merge_aggregation(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Catches a stable terminal context accepting any non-success lane or admitted=false."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / ".github/workflows/merge-gate-v1.yml"
    raw = path.read_text(encoding="utf-8")
    if mutation == "missing-result":
        raw = raw.replace("          test '${{ needs.security.result }}' = success\n", "")
    elif mutation == "weak-result":
        raw = raw.replace(
            "          test '${{ needs.security.result }}' = success",
            "          test '${{ needs.security.result }}' != failure",
        )
    else:
        raw = raw.replace(
            "          test '${{ needs.final-candidate.outputs.admitted }}' = true",
            "          test '${{ needs.final-candidate.outputs.admitted }}' = false",
        )
    path.write_text(raw, encoding="utf-8")

    with pytest.raises(ValueError, match="terminal gate aggregation"):
        load_validator().validate_workflow(fixture)


def test_all_profile_execution_lanes_are_real_or_explicitly_not_applicable() -> None:
    """Catches target runtime diagnostics becoming authoritative before the supervisor canary."""
    for profile, workflow_name in PROFILE_WORKFLOWS.items():
        raw = (ROOT / ".github/workflows" / workflow_name).read_text(encoding="utf-8")
        workflow = yaml.safe_load(raw)
        deterministic = workflow["jobs"]["deterministic"]
        runner = next(step for step in deterministic["steps"] if step.get("name") == "Run deterministic profile")
        assert "profile_runner.py --execute" in runner["run"]
        assert "--lane deterministic" in runner["run"]
        assert "consumer-profile-owner-execution-canary blocks" not in raw
        security = workflow["jobs"]["security"]
        required = next(step for step in security["steps"] if step.get("name") == "Run required security profile")
        not_applicable = next(
            step for step in security["steps"] if step.get("name") == "Record explicit security not-applicable"
        )
        assert "--lane security" in required["run"]
        assert "not-applicable" in not_applicable["run"]
        assert "run_isolated_runtime.py" in raw
        assert "verify_runtime_evidence.py" in raw
        assert "Fail closed pending unforgeable target-supervisor hosted canary" in raw
        if profile in {"node", "powershell"}:
            assert "python -m pytest" not in raw
            assert "python -m bandit" not in raw


def test_continuous_validation_provisions_pinned_runtime_and_dependencies() -> None:
    """Catches source development losing its one distinct, pinned validation workflow."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/continuous-validation.yml").read_text(encoding="utf-8"))
    events = workflow.get(True, workflow.get("on", {}))
    assert set(events) == {"pull_request", "merge_group", "push", "schedule"}
    assert events["pull_request"] is None
    assert events["merge_group"] is None
    assert events["push"] == {"branches": ["main"]}
    assert workflow["name"] == "Koios CI / continuous validation"
    assert workflow["concurrency"] == {
        "group": (
            "continuous-validation-${{ github.repository_id }}-${{ github.event_name }}-${{ "
            "github.event_name == 'pull_request' && github.event.pull_request.number || github.run_id }}"
        ),
        "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
    }

    def expected_concurrency(event_name: str, *, pull_request_number: int, run_id: int) -> tuple[str, bool]:
        identity = pull_request_number if event_name == "pull_request" else run_id
        return f"continuous-validation-42-{event_name}-{identity}", event_name == "pull_request"

    assert expected_concurrency("pull_request", pull_request_number=17, run_id=100) == expected_concurrency(
        "pull_request", pull_request_number=17, run_id=101
    )
    non_pull_request = {
        expected_concurrency(event_name, pull_request_number=17, run_id=run_id)
        for event_name, run_id in (
            ("merge_group", 200),
            ("merge_group", 201),
            ("push", 200),
            ("push", 201),
            ("schedule", 200),
            ("schedule", 201),
        )
    }
    assert len(non_pull_request) == 6
    assert all(cancel_in_progress is False for _, cancel_in_progress in non_pull_request)
    assert workflow["jobs"]["validation"]["name"] == "Koios CI / source validation"
    assert all(job.get("name") != "CI / required" for job in workflow["jobs"].values())
    source_capable_workflows: list[str] = []
    source_triggers = {"pull_request", "merge_group", "push", "schedule"}
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        candidate = yaml.safe_load(path.read_text(encoding="utf-8"))
        candidate_events = candidate.get(True, candidate.get("on", {})) if isinstance(candidate, dict) else {}
        if not isinstance(candidate_events, dict) or not source_triggers & set(candidate_events):
            continue
        if path.name == "continuous-validation.yml":
            source_capable_workflows.append(path.name)
            continue
        candidate_jobs = candidate.get("jobs", {})
        if any(
            not (
                str(job.get("if", "")) == SOURCE_REPOSITORY_GUARD
                or (
                    str(job.get("if", "")).startswith(f"{SOURCE_REPOSITORY_GUARD} && ")
                    and "||" not in str(job.get("if", ""))
                )
            )
            for job in candidate_jobs.values()
            if isinstance(job, dict)
        ):
            source_capable_workflows.append(path.name)
    assert source_capable_workflows == ["continuous-validation.yml"]
    steps = workflow["jobs"]["validation"]["steps"]
    python_setup = next(step for step in steps if step.get("name") == "Set up pinned Python")
    assert python_setup["uses"] == "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
    assert python_setup["with"]["python-version"] == "3.12.13"
    install = next(step for step in steps if step.get("name") == "Install pinned validation dependencies")
    assert "requirements-dev.txt" in install["run"]
    integrity = next(step for step in steps if step.get("name") == "Verify validation dependency integrity")
    assert "pip check" in integrity["run"]
    validate = next(step for step in steps if step.get("name") == "Validate immutable platform contract")
    assert "--structural-only" in validate["run"]
    generator = next(step for step in steps if step.get("name") == "Reject generated workflow drift")
    assert "generate_merge_gate_profiles.py --root . --check" in generator["run"]
    ruff_check = next(step for step in steps if step.get("name") == "Lint platform source")
    assert ruff_check["run"] == "python -m ruff check . --no-cache"
    ruff_format = next(step for step in steps if step.get("name") == "Check platform formatting")
    assert ruff_format["run"] == "python -m ruff format --check . --no-cache"
    mypy = next(step for step in steps if step.get("name") == "Type-check all platform scripts")
    assert mypy["run"] == "python -m mypy scripts --ignore-missing-imports"
    pytest_steps = [step for step in steps if str(step.get("name", "")).startswith("Test platform with plugins")]
    assert len(pytest_steps) == 2
    by_name = {step["name"]: step for step in pytest_steps}
    assert by_name["Test platform with plugins auto-loaded"]["run"] == (
        'python -B -m pytest tests -q -n 2 -k "not test_complete_platform_suite_runs_in_each_plugin_mode"'
    )
    assert by_name["Test platform with plugins disabled"]["run"] == (
        "python -B -m pytest tests -q -p xdist.plugin -n 2 "
        '-k "not test_complete_platform_suite_runs_in_each_plugin_mode"'
    )
    assert "env" not in by_name["Test platform with plugins auto-loaded"]
    assert by_name["Test platform with plugins disabled"]["env"] == {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}


@pytest.mark.parametrize(
    "forbidden",
    [
        "${{ job.workflow_sha }}",
        "${{ runner.temp }}/evidence",
        "${{job.workflow_sha}}",
        "${{  runner.temp }}",
        "${{ job['workflow_sha'] }}",
        '${{ runner["temp"] }}',
        "${{ job [ 'workflow_sha' ] }}",
        "${{ JOB.workflow_sha }}",
        "${{ format('{0}', runner.temp) }}",
        "${{ format('{{literal}} {0}', runner.temp) }}",
        "${{ github.actor != '' && job['workflow_sha'] }}",
        "${{ toJSON(runner) }}",
        "${{ toJSON(job) }}",
        "${{\n  format('{0}', runner.temp)\n}}",
    ],
)
def test_validator_rejects_job_env_contexts_unavailable_at_job_scope(tmp_path: Path, forbidden: str) -> None:
    """Catches a workflow GitHub rejects before creating any job."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / ".github/workflows/continuous-validation.yml"
    raw = path.read_text(encoding="utf-8")
    if "\n" in forbidden:
        serialized_value = "      FORBIDDEN_CONTEXT: |-\n" + "".join(
            f"        {line}\n" for line in forbidden.splitlines()
        )
    else:
        serialized_value = "      FORBIDDEN_CONTEXT: " + forbidden + "\n"
    raw = raw.replace(
        "    name: Koios CI / source validation\n",
        "    name: Koios CI / source validation\n    env:\n" + serialized_value,
        1,
    )
    path.write_text(raw, encoding="utf-8")

    with pytest.raises(ValueError, match="unavailable at job-level env scope"):
        load_validator().validate_workflow(fixture)


@pytest.mark.parametrize(
    "allowed",
    [
        "${{ vars.runner.temp }}",
        "${{ 'runner.temp' }}",
        "${{ format('runner.temp') }}",
        "${{ contains('prefix runner.temp', vars.value) }}",
        "${{ contains('it''s job.workflow_sha', vars.value) }}",
    ],
)
def test_validator_allows_non_root_job_runner_text_in_job_env(tmp_path: Path, allowed: str) -> None:
    """Distinguishes unavailable root contexts from properties and quoted text."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / ".github/workflows/continuous-validation.yml"
    raw = path.read_text(encoding="utf-8").replace(
        "    name: Koios CI / source validation\n",
        f"    name: Koios CI / source validation\n    env:\n      ALLOWED_CONTEXT_TEXT: {allowed}\n",
        1,
    )
    path.write_text(raw, encoding="utf-8")

    load_validator().validate_workflow(fixture)


def test_v1_validator_rejects_a_floating_control_plane_python_minor(tmp_path: Path) -> None:
    """Catches setup-python silently resolving a newer patch in admission jobs."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / ".github/workflows/merge-gate-v1.yml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            'python-version: "3.12.13"',
            'python-version: "3.12"',
            1,
        ),
        encoding="utf-8",
    )

    result = run_validator(fixture)

    assert result.returncode != 0
    assert "Python patch version" in result.stderr


def test_v1_contract_keeps_merge_gate_release_explicitly_not_ready() -> None:
    """Catches a local workflow shape being misrepresented as hosted admission proof."""
    contract = json.loads((ROOT / "contract/v1.json").read_text(encoding="utf-8"))

    assert contract["x-merge-gate-v1"] == {
        "profile_workflows": {
            profile: f".github/workflows/{workflow}" for profile, workflow in PROFILE_WORKFLOWS.items()
        },
        "profiles": ["baseline", "python", "node", "powershell", "critical-ml"],
        "profile_selection": {
            "authority": "separate-organization-rulesets",
            "target_filter_template": "props.ci_profile:<profile>",
            "assignment_authority": "explicit-user-specified-only",
            "runtime_custom_property_input": False,
            "one_active_required_workflow_per_repository": True,
            "hosted_readback_required": True,
        },
        "source_repository_policy": {
            "repository": SOURCE_REPOSITORY,
            "profile_workflow_jobs": "disabled",
            "consumer_required_context": "CI / required",
            "source_disabled_contexts": SOURCE_DISABLED_JOB_NAMES,
            "internal_workflow": ".github/workflows/continuous-validation.yml",
            "internal_job": "Koios CI / source validation",
            "internal_triggers": ["pull_request", "merge_group", "push-main", "schedule"],
        },
        "profile_property": {
            "name": "ci_profile",
            "owner": "organization",
            "type": "single_select",
            "required": True,
            "assignment_mode": "explicit-user-specified",
            "default_value": None,
            "inheritance_permitted": False,
            "empty_value_permitted": False,
            "allowed_values": ["baseline", "python", "node", "powershell", "critical-ml"],
            "repository_actor_updates": False,
        },
        "profile_rulesets": [
            {
                "name": f"Koios CI / {profile} merge gate",
                "branch_target": "~DEFAULT_BRANCH",
                "target_filter": f"props.ci_profile:{profile}",
                "required_workflow": f".github/workflows/{workflow}",
                "required_job": "CI / required",
            }
            for profile, workflow in PROFILE_WORKFLOWS.items()
        ],
        "terminal_job": {"id": "merge", "name": "CI / required"},
        "common_security": {
            "status": "required-all-profiles",
            "tool": "scripts/secret_scan.py",
            "tool_version": "1.0.0",
            "config": "contract/secret-scan-v1.json",
            "config_sha256": "19f447a775d4f15bf6a4f5be044d1a258166af06c3d253ca4a0b6122a740eb5c",
            "positive_canary": "tests/canaries/secrets/pass.txt",
            "negative_canary_parts": [
                "tests/canaries/secrets/token-prefix.txt",
                "tests/canaries/secrets/token-suffix.txt",
            ],
            "negative_exit": 2,
            "target_scope": "git-tracked-files",
            "target_code_execution": False,
        },
        "policy_model": "scripts/merge_gate_policy.py",
        "profile_runner": "scripts/profile_runner.py --execute --lane <lane>",
        "legacy_v1_candidates": [],
        "local_validation_authority": "structural-only-non-authoritative",
        "release_status": "NOT READY",
        "release_blockers": [
            "profile-ruleset-hosted-readback",
            "draft-to-ready-hosted-rerun-canary",
            "merge-group-ai-mapping-canary",
            "provider-native-exact-head-canaries",
            "deepsource-retain-or-replace-dispositions-and-ai-review-disabled-readback",
            "untrusted-runtime-evidence-hosted-canary",
            "runtime-output-bounded-supervisor-hosted-canary",
            "protected-affected-test-supervisor-canary",
            "mypy-adoption-ratchet-hosted-canary",
            "first-critical-consumer-test-policy-v1-migration",
            "first-critical-consumer-python-manifest-v1-migration",
            "coderabbit-cost-controls-hosted-readback",
            "codex-cost-controls-hosted-readback",
            "deepsource-ai-cost-controls-hosted-readback",
            "trusted-same-run-source-attestation-adapter-wiring",
            "complete-graphql-equivalent-review-thread-resolution-readback",
            "immutable-workflow-promoter-identities",
            "exact-label-invalidation-same-sha-lifecycle-controller",
            "complete-same-pr-head-run-inventory-no-newer-failure",
            "github-native-transactional-single-flight-across-hosted-runners",
            "github-code-quality-org-no-repositories-enforced-readback",
            "github-code-quality-billing-cessation-readback",
            "node-corepack-manager-artifact-digests",
            "powershell-pester-artifact-digest",
            "hash-locked-platform-toolchain-or-digest-pinned-image",
        ],
    }


def test_v1_contract_closes_ai_cost_controls_and_future_dependabot_exemption() -> None:
    """Catches paid-provider overage or a sender/head-unbound future bot exemption."""
    contract = json.loads((ROOT / "contract/v1.json").read_text(encoding="utf-8"))
    assert contract["x-coderabbit-policy"] == {
        "path": ".coderabbit.yaml",
        "source": "exact-platform-template",
        "profile": "assertive",
        "label_opt_in": "ai-review-ready",
        "review_cadence": "final-only-label-opt-in",
        "automatic_review": False,
        "incremental_review": False,
        "draft_review": False,
        "autofix": False,
        "write_capable_finishing_touches": False,
        "usage_based_add_on": "disabled",
        "recurring_credit_purchases": False,
        "automatic_credit_top_up": False,
        "rate_limit_exhaustion": "fail-closed-wait-no-provider-pass",
        "organization_override_readback_required": True,
    }
    assert contract["x-codex-policy"] == {
        "review_cadence": "exact-head-final-only",
        "provider_pass_requires_exact_head": True,
        "purchased_credits_enabled": False,
        "automatic_credit_reload": False,
        "usage_overage_permitted": False,
        "quota_exhaustion": "fail-closed-wait-no-provider-pass",
        "hosted_readback_required": True,
    }
    assert contract["x-deepsource-policy"] == {
        "subscription": "team-fixed-30-usd-per-month-per-contributor",
        "deterministic_analysis_enabled": True,
        "sca_enabled": True,
        "fail_on_no_data_enabled": True,
        "checked_in_deepsource_toml_enabled": True,
        "master_ai_agents_enabled": False,
        "automatic_ai_credit_recharge_enabled": False,
        "ai_features_required_disabled": [
            "ai-review",
            "ai-autofix",
            "enhanced-secrets-ai",
            "pr-report-card-ai",
        ],
        "ai_review_context_permitted": False,
        "hosted_feature_readback_required": True,
        "observed_on": "2026-07-27",
    }
    assert contract["x-github-code-quality-policy"] == {
        "state": "disabled",
        "policy": "permanent-exclusion",
        "observed_control": "Enable Code Quality",
        "context_present": False,
        "configuration_present": False,
        "canary_present": False,
        "organization_repository_access_required": "no-repositories",
        "organization_repository_access_enforcement_required": True,
        "organization_repository_access_receipt": None,
        "billing_cessation_receipt": None,
        "reactivation_permitted": False,
        "replacement": "contract/deterministic-quality-v1.json",
        "observed_on": "2026-07-27",
    }
    assert contract["x-platform-toolchain-integrity"] == {
        "control_plane_python": "3.12.13",
        "requirements_file": "requirements-dev.txt",
        "requirements_state": "exact-versions-without-hashes",
        "immutable_supply_chain_proven": False,
        "required_resolution": [
            "hash-locked-requirements-with-require-hashes",
            "digest-pinned-prebuilt-control-plane-image",
        ],
    }
    assert contract["x-sha-invalidation-controller"] == {
        "implementation_status": "implemented-hosted-unverified",
        "design_template": "templates/consumer/.github/workflows/invalidate-final-labels.yml",
        "planned_consumer_path": ".github/workflows/invalidate-final-labels.yml",
        "platform_canary_workflow": ".github/workflows/invalidate-final-labels.yml",
        "required_source": "trusted-default-branch",
        "hosted_readback_required": True,
        "events": [
            "pull_request_target:synchronize",
            "pull_request_target:reopened",
            "pull_request_target:converted_to_draft",
        ],
        "labels": ["ai-review-ready", "ci-final"],
        "labels_only": True,
        "required_check_contexts_invalidated": False,
        "same_sha_lifecycle_transitions_blocked_until_external_enforcement": [
            "closed-to-reopened",
            "draft-to-ready",
        ],
    }
    assert contract["x-exact-head-finalizer"] == {
        "implementation_status": "local-complete-hosted-unverified",
        "subject_template": "templates/consumer/.github/workflows/final-subject-v1.yml",
        "controller_template": "templates/consumer/.github/workflows/finalize-python-v1.yml",
        "resume_template": "templates/consumer/.github/workflows/resume-finalizer-v1.yml",
        "dispatch_action": ".github/actions/dispatch-finalizer",
        "subject_run_name": "koios-final-subject-v1",
        "controller_run_name": "koios-finalizer-v1",
        "source_attestation_schema": "koios-run-source-v3",
        "source_commit_binding": "controller-and-subject-head-sha-equal-pr-base-sha",
        "complete_review_thread_pagination": True,
        "complete_same_head_attempt_inventory": True,
        "gate_job_names": {
            "deterministic": "Platform / deterministic final evidence",
            "security": "Platform / security evidence",
            "coverage": "Platform / coverage evidence verification",
        },
        "github_caller_job_prefix_permitted": True,
        "cross_run_singleflight": "github-actions-concurrency-repository-pr-head",
        "cancel_in_progress": False,
        "broad_rerun_endpoint_permitted": False,
        "resume_mode": "automatic-workflow-run-completed-bound-to-exact-subject-run-and-attempt",
        "hosted_readback_flags_default_false": True,
        "codex_hosted_canary_default": "disabled",
        "codex_native_result": "exact-current-review-body-PASS",
        "cutover_permitted": False,
    }
    assert contract["x-dependabot-policy"]["paid_ai_exemption_active"] is False
    assert contract["x-dependabot-policy"]["future_exemption_binding_required"] == {
        "pull_request_actor": "dependabot[bot]-exact-app-identity",
        "event_sender": "dependabot[bot]-exact-app-identity",
        "event_name": "pull_request",
        "repository": "same-repository-id-and-full-name",
        "pull_request_number": "exact-current-pull-request",
        "head_sha": "exact-current-head",
        "base_sha": "exact-current-base",
        "changed_paths": "dependency-only-full-copy-rename-delete-proof",
    }


def test_valid_code_quality_receipts_can_close_only_their_release_blockers(tmp_path: Path) -> None:
    """Catches permanently-null evidence slots that make billing/access closure unrepresentable."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / "contract/v1.json"
    contract = json.loads(path.read_text(encoding="utf-8"))
    policy = contract["x-github-code-quality-policy"]
    policy["organization_repository_access_receipt"] = hosted_state_receipt(
        "organization-code-quality-repository-access",
        {"repository_access": "no-repositories", "enforced": True},
    )
    policy["billing_cessation_receipt"] = hosted_state_receipt(
        "organization-code-quality-billing",
        {"billing_state": "ceased", "future_charges": False},
    )
    blockers = contract["x-merge-gate-v1"]["release_blockers"]
    blockers.remove("github-code-quality-org-no-repositories-enforced-readback")
    blockers.remove("github-code-quality-billing-cessation-readback")
    path.write_text(json.dumps(contract), encoding="utf-8")

    load_validator().validate_profile_contract(fixture)


@pytest.mark.parametrize(
    "mutation",
    [
        "stale",
        "bad-digest",
        "unauthenticated",
        "wrong-source",
        "wrong-provider",
        "contradictory-state",
        "invalid-reviewer",
    ],
)
def test_code_quality_receipts_reject_stale_malformed_or_contradictory_evidence(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Catches self-asserted or stale hosted state closing permanent-exclusion blockers."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / "contract/v1.json"
    contract = json.loads(path.read_text(encoding="utf-8"))
    policy = contract["x-github-code-quality-policy"]
    access = hosted_state_receipt(
        "organization-code-quality-repository-access",
        {"repository_access": "no-repositories", "enforced": True},
    )
    billing = hosted_state_receipt(
        "organization-code-quality-billing",
        {"billing_state": "ceased", "future_charges": False},
    )
    policy["organization_repository_access_receipt"] = access
    policy["billing_cessation_receipt"] = billing
    blockers = contract["x-merge-gate-v1"]["release_blockers"]
    blockers.remove("github-code-quality-org-no-repositories-enforced-readback")
    blockers.remove("github-code-quality-billing-cessation-readback")

    if mutation == "stale":
        access["captured_at"] = "2026-01-01T00:00:00Z"
    elif mutation == "bad-digest":
        access["sha256"] = "0" * 64
    elif mutation == "unauthenticated":
        access["authentication"]["authenticated"] = False
    elif mutation == "wrong-source":
        access["source"]["organization"] = "other-org"
    elif mutation == "wrong-provider":
        access["provider"]["domain"] = "example.invalid"
    elif mutation == "contradictory-state":
        access["state"]["repository_access"] = "all-repositories"
    else:
        access["reviewer"]["id"] = 0
    if mutation != "bad-digest":
        payload = dict(access)
        payload.pop("sha256")
        access["sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    path.write_text(json.dumps(contract), encoding="utf-8")

    with pytest.raises(ValueError, match=r"Code Quality|receipt|captured|authentication|provider|state|reviewer"):
        load_validator().validate_profile_contract(fixture)


@pytest.mark.parametrize(
    "mutation",
    [
        "inherited-profile",
        "default-profile",
        "non-default-branch-target",
        "coderabbit-top-up",
        "codex-overage",
        "deepsource-recharge",
        "code-quality-enabled",
        "code-quality-repositories-enabled",
        "code-quality-reactivation",
        "missing-code-quality-org-blocker",
        "missing-code-quality-billing-blocker",
        "toolchain-claimed-proven",
        "implemented-invalidation",
        "dependabot-unbound-sender",
        "missing-runtime-supervisor-blocker",
    ],
)
def test_v1_contract_validator_rejects_governance_cost_or_exemption_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Catches profile ambiguity, cost overage, weak bot binding, or premature runtime readiness."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / "contract/v1.json"
    contract = json.loads(path.read_text(encoding="utf-8"))
    merge_gate = contract["x-merge-gate-v1"]
    if mutation == "inherited-profile":
        merge_gate["profile_property"]["inheritance_permitted"] = True
    elif mutation == "default-profile":
        merge_gate["profile_property"]["default_value"] = "baseline"
    elif mutation == "non-default-branch-target":
        merge_gate["profile_rulesets"][0]["branch_target"] = "refs/heads/main"
    elif mutation == "coderabbit-top-up":
        contract["x-coderabbit-policy"]["automatic_credit_top_up"] = True
    elif mutation == "codex-overage":
        contract["x-codex-policy"]["usage_overage_permitted"] = True
    elif mutation == "deepsource-recharge":
        contract["x-deepsource-policy"]["automatic_ai_credit_recharge_enabled"] = True
    elif mutation == "code-quality-enabled":
        contract["x-github-code-quality-policy"]["state"] = "enabled"
    elif mutation == "code-quality-repositories-enabled":
        contract["x-github-code-quality-policy"]["organization_repository_access_required"] = "all-repositories"
    elif mutation == "code-quality-reactivation":
        contract["x-github-code-quality-policy"]["reactivation_permitted"] = True
    elif mutation == "missing-code-quality-org-blocker":
        merge_gate["release_blockers"].remove("github-code-quality-org-no-repositories-enforced-readback")
    elif mutation == "missing-code-quality-billing-blocker":
        merge_gate["release_blockers"].remove("github-code-quality-billing-cessation-readback")
    elif mutation == "toolchain-claimed-proven":
        contract["x-platform-toolchain-integrity"]["immutable_supply_chain_proven"] = True
    elif mutation == "implemented-invalidation":
        contract["x-sha-invalidation-controller"]["implementation_status"] = "hosted-verified"
    elif mutation == "dependabot-unbound-sender":
        contract["x-dependabot-policy"]["future_exemption_binding_required"].pop("event_sender")
    else:
        merge_gate["release_blockers"].remove("runtime-output-bounded-supervisor-hosted-canary")
    path.write_text(json.dumps(contract), encoding="utf-8")

    with pytest.raises(ValueError, match=r"profile|cost|Dependabot|toolchain|invalidation|release blocker"):
        load_validator().validate_profile_contract(fixture)


@pytest.mark.parametrize(
    "mutation",
    [
        "legacy-ignore",
        "wrong-desired-state",
        "missing-disabled-readback",
        "ignore-observed-context",
        "legacy-blocker",
        "retirement-blocker",
    ],
)
def test_v1_contract_validator_rejects_non_fail_closed_ai_review_owner_policy(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Catches post-disablement AI Review contexts being ignored or broad DeepSource retirement being required."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / "contract/v1.json"
    contract = json.loads(path.read_text(encoding="utf-8"))
    native_evidence = contract["x-context-owners"]["Security / required"]["native_provider_evidence"]
    native_evidence.pop("ignore_unconfigured_ai_review_except_failure", None)
    native_evidence.update(
        {
            "ai_review_desired_state": "disabled",
            "ai_review_disabled_readback_required": True,
            "observed_ai_review_context_policy": "fail-closed-hosted-drift",
        }
    )
    blocker = "deepsource-retain-or-replace-dispositions-and-ai-review-disabled-readback"
    if mutation == "legacy-ignore":
        native_evidence["ignore_unconfigured_ai_review_except_failure"] = True
    elif mutation == "wrong-desired-state":
        native_evidence["ai_review_desired_state"] = "enabled"
    elif mutation == "missing-disabled-readback":
        native_evidence.pop("ai_review_disabled_readback_required")
    elif mutation == "ignore-observed-context":
        native_evidence["observed_ai_review_context_policy"] = "ignore-unconfigured-except-failure"
    elif mutation == "legacy-blocker":
        index = contract["x-merge-gate-v1"]["release_blockers"].index(blocker)
        contract["x-merge-gate-v1"]["release_blockers"][index] = "deepsource-disposition-and-readbacks"
    else:
        contract["x-merge-gate-v1"]["release_blockers"].append("deepsource-retirement")
    path.write_text(json.dumps(contract), encoding="utf-8")

    with pytest.raises(ValueError, match=r"AI Review|DeepSource"):
        load_validator().validate_profile_contract(fixture)


def test_v1_contract_validator_rejects_a_mutable_platform_source_selector(tmp_path: Path) -> None:
    """Catches replacing the immutable running-workflow SHA with a branch selector."""
    fixture = copy_contract_fixture(tmp_path)
    path = fixture / ".github/workflows/merge-gate-v1.yml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "ref: ${{ job.workflow_sha }}",
            "ref: refs/heads/main",
        ),
        encoding="utf-8",
    )

    result = run_validator(fixture)

    assert result.returncode != 0
    assert "immutable platform source" in result.stderr
