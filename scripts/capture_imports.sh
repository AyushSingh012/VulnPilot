#!/usr/bin/env bash
# Regenerate the sample Trivy / Wiz files in tests/data/imports from a VulnPilot fixture,
# so they hold no data from any real project. Wiz needs a logged-in wizcli; skip it with
# NO_WIZ=1. Wiz files are passed through scripts/scrub_wiz.py (tenant ids and URLs).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/tests/data/imports"
fixture="$root/tests/fixtures/uv/tests-break"
img="vulnpilot-sample:local"

docker build -q -t "$img" "$out" >/dev/null
trivy fs --scanners vuln --format json --quiet --output "$out/trivy-fs.json" "$fixture"
trivy image --scanners vuln --format json --quiet --output "$out/trivy-image.json" "$img"
if [[ "${NO_WIZ:-}" != 1 ]]; then
  wizcli scan dir "$fixture" --by-policy-hits DISABLED --json-output-file "$out/wiz-dir.raw.json" >/dev/null || true
  wizcli scan container-image "$img" --by-policy-hits DISABLED --json-output-file "$out/wiz-image.raw.json" >/dev/null || true
  for kind in dir image; do
    uv run python "$root/scripts/scrub_wiz.py" "$out/wiz-$kind.raw.json" "$out/wiz-$kind.json"
    rm -f "$out/wiz-$kind.raw.json"
  done
fi
# Trivy records the absolute fixture path; keep it relative.
sed -i.bak "s#$root/##g" "$out/trivy-fs.json" && rm -f "$out/trivy-fs.json.bak"
