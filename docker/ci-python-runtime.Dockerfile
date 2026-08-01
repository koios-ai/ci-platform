FROM python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ENV PATH="/opt/ci-platform-venv/bin:${PATH}" \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY requirements-dev.txt /tmp/ci-platform-requirements-dev.txt
RUN python -m venv /opt/ci-platform-venv \
    && /opt/ci-platform-venv/bin/python -m pip install --requirement /tmp/ci-platform-requirements-dev.txt \
    && /opt/ci-platform-venv/bin/python -m pip check \
    && rm /tmp/ci-platform-requirements-dev.txt

COPY contract/coverage-v1.ini contract/mypy-v1.ini contract/pytest-v1.ini /opt/ci-platform/contract/
COPY scripts/run_module_isolated.py scripts/run_platform_script.py scripts/run_pytest_isolated.py scripts/run_test_policy.py scripts/test_policy.py /opt/ci-platform/scripts/
RUN chmod -R a-w /opt/ci-platform /opt/ci-platform-venv

WORKDIR /workspace/target
USER 65532:65532
ENTRYPOINT ["/opt/ci-platform-venv/bin/python"]
