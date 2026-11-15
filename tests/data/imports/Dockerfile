# Sample image for VulnPilot's import tests; built and scanned by scripts/capture_imports.sh.
# Matches tests/fixtures/uv/tests-break: requests and jinja2 at the lockfile's versions,
# urllib3 older than the lockfile's (FIXED_IN_SOURCE), setuptools not in the lockfile at
# all (OUT_OF_SCOPE). Alpine packages are OS findings (OUT_OF_SCOPE).
FROM python:3.12-alpine
RUN pip install --no-cache-dir --root-user-action=ignore \
    requests==2.31.0 jinja2==3.1.2 urllib3==2.2.1 setuptools==65.5.0
