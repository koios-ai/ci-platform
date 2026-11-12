from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

OWNER = Path(__file__).resolve().parents[1] / ".github/actions/final-preflight/path_feed_owner.py"


@pytest.fixture
def owner(monkeypatch):
    spec = importlib.util.spec_from_file_location("path_feed_owner", OWNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


class Session:
    def __init__(self, owner):
        self.owner = owner
        self.now = 1.0
        self.calls = []
        self.errors = {}
        self.times = {}
        self.exit_code = 0
        self.framed = True
        self.descendants_closed = True
        self.writers_closed = True

    def step(self, action, deadline):
        self.calls.append((action, deadline))
        self.now = self.times.get(action, self.now)
        if action in self.errors:
            raise self.errors[action]

    def establish(self, deadline):
        self.step("establish", deadline)

    def fetch(self, deadline):
        self.step("fetch", deadline)
        return self.owner.TransferTerminal(self.exit_code, self.framed)

    def revoke_bridge(self, deadline):
        self.step("revoke", deadline)

    def observe_closure(self, deadline):
        self.step("closure", deadline)
        return self.owner.OwnerClosure(self.descendants_closed, self.writers_closed)

    def quarantine(self, deadline):
        self.step("quarantine", deadline)

    def terminate_and_reap(self, deadline):
        self.step("terminate", deadline)
        return self.owner.OwnerClosure(self.descendants_closed, self.writers_closed)

    def verify_offline(self, deadline):
        self.step("offline", deadline)
        return (".github/workflows/old.yml", "src/features/original.py")

    def refresh_pr(self, deadline):
        self.step("refresh", deadline)

    @property
    def actions(self):
        return [action for action, _ in self.calls]

    def run(self):
        return self.owner.acquire(self, deadline=10.0, clock=lambda: self.now)


def test_owner_requires_bridge_and_whole_owner_closure_before_offline_observation(owner):
    session = Session(owner)

    assert session.run() == (".github/workflows/old.yml", "src/features/original.py")
    assert session.actions == ["establish", "fetch", "revoke", "closure", "offline", "refresh"]
    assert all(deadline == 10.0 for _, deadline in session.calls)


@pytest.mark.parametrize("limit", ["store quota", "process isolation", "wire cap"])
def test_owner_refuses_before_fetch_when_a_limit_cannot_be_established(owner, limit):
    session = Session(owner)
    session.errors["establish"] = RuntimeError(limit)

    with pytest.raises(RuntimeError, match=limit):
        session.run()

    assert session.actions == ["establish", "revoke", "quarantine", "terminate"]


@pytest.mark.parametrize("fault", ["worker ingress", "wire read-ahead"])
def test_owner_revokes_and_quarantines_on_transport_limit_failure(owner, fault):
    session = Session(owner)
    session.errors["fetch"] = RuntimeError(f"{fault} byte limit")

    with pytest.raises(RuntimeError, match="byte limit"):
        session.run()

    assert session.actions == ["establish", "fetch", "revoke", "quarantine", "terminate"]


@pytest.mark.parametrize("field", ["descendants_closed", "writers_closed"])
@pytest.mark.parametrize("outcome", [False, None])
def test_zero_git_exit_cannot_admit_live_or_unobserved_owner(owner, field, outcome):
    session = Session(owner)
    setattr(session, field, outcome)

    with pytest.raises(ExceptionGroup) as error:
        session.run()

    assert session.exit_code == 0
    assert "owner closure" in str(error.value.exceptions[0])
    assert "cleanup closure" in str(error.value.exceptions[1])
    assert session.actions == ["establish", "fetch", "revoke", "closure", "quarantine", "terminate"]


def test_zero_git_exit_cannot_admit_an_incomplete_transfer(owner):
    session = Session(owner)
    session.framed = False

    with pytest.raises(owner.AcquisitionRefused, match="incomplete transfer"):
        session.run()

    assert session.actions == ["establish", "fetch", "revoke", "quarantine", "terminate"]


@pytest.mark.parametrize("action", ["establish", "fetch", "revoke", "closure", "offline", "refresh"])
def test_deadline_is_checked_after_each_action_before_admission(owner, action):
    session = Session(owner)
    session.times[action] = 10.0

    with pytest.raises(TimeoutError, match="deadline"):
        session.run()

    assert session.actions.count(action) == 1
    assert session.actions[-2:] == ["quarantine", "terminate"]
    assert session.calls[-1][1] > 10.0


@pytest.mark.parametrize("fault", ["wrong head", "missing ancestry", "promisor", "alternate store"])
def test_offline_verification_failure_cannot_refresh_or_admit(owner, fault):
    session = Session(owner)
    session.errors["offline"] = RuntimeError(fault)

    with pytest.raises(RuntimeError, match=fault):
        session.run()

    assert session.actions == ["establish", "fetch", "revoke", "closure", "offline", "quarantine", "terminate"]


def test_cleanup_attempts_all_steps_and_keeps_original_failure(owner):
    session = Session(owner)
    session.errors.update(
        fetch=RuntimeError("primary transfer failure"),
        revoke=RuntimeError("revocation failed"),
        terminate=RuntimeError("reaping unknown"),
    )

    with pytest.raises(ExceptionGroup) as error:
        session.run()

    assert [str(item) for item in error.value.exceptions] == [
        "primary transfer failure",
        "revocation failed",
        "reaping unknown",
    ]
    assert session.actions == ["establish", "fetch", "revoke", "quarantine", "terminate"]


def test_already_expired_deadline_opens_no_session_resources(owner):
    session = Session(owner)
    session.now = 10.0

    with pytest.raises(TimeoutError, match="deadline"):
        session.run()

    assert not session.calls
