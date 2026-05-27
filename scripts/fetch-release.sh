#!/usr/bin/env bash
# fetch-release.sh — download a tagged membrane-daemon release from
# GitHub and push the binaries to the cloud's downloads dir.
#
# Workflow:
#   1. Tag locally: `git tag v0.1.0 && git push --tags`
#   2. GitHub Actions builds for all platforms, attaches binaries to release.
#   3. Wait ~15 minutes for the release to complete.
#   4. Run this script: `./scripts/fetch-release.sh v0.1.0`

set -eu

TAG="${1:-}"
if [ -z "$TAG" ]; then
    echo "usage: $0 <tag>"
    echo "       $0 v0.1.0"
    exit 2
fi

# Operator-side script — these defaults match the membrane.informationpatterns.com
# deployment. Override via env vars for other deployments.
REPO="${MEMBRANE_DAEMON_REPO:-adamth0mps0n/Membrane-daemon}"
CLOUD_HOST="${MEMBRANE_CLOUD_HOST:?set MEMBRANE_CLOUD_HOST (e.g. root@cloud.example.com)}"
CLOUD_DIR="${MEMBRANE_CLOUD_DIR:-/var/lib/membrane-cloud/downloads}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "[1/4] fetching release $TAG from $REPO"
URLS=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/tags/$TAG" \
       | python3 -c "
import sys, json
r = json.load(sys.stdin)
for asset in r.get('assets', []):
    print(asset['browser_download_url'])
")

if [ -z "$URLS" ]; then
    echo "no assets found for $TAG. did the workflow complete?"
    exit 1
fi

for url in $URLS; do
    echo "  downloading $(basename "$url")"
    curl -fsSL --progress-bar "$url" -O
done
ls -la

echo
echo "[2/4] verifying hashes match manifest"
if [ ! -f manifest.json ]; then
    echo "manifest.json missing — refusing to upload binaries that aren't manifest-verified"
    exit 1
fi

if ! command -v b3sum >/dev/null 2>&1; then
    echo "b3sum not installed (cargo install b3sum)"
    exit 1
fi

python3 <<PY
import json, subprocess, sys, pathlib
with open('manifest.json') as f:
    manifest = json.load(f)

failures = []
for name, entry in manifest['files'].items():
    if not pathlib.Path(name).exists():
        print(f"  missing local file: {name}")
        failures.append(name)
        continue
    out = subprocess.run(['b3sum', '--no-names', name], capture_output=True, text=True, check=True)
    actual = out.stdout.strip()
    expected = entry['blake3']
    if actual != expected:
        print(f"  HASH MISMATCH: {name}")
        print(f"    expected {expected}")
        print(f"    actual   {actual}")
        failures.append(name)
    else:
        print(f"  ok: {name} ({entry['blake3'][:16]}...)")

if failures:
    sys.exit(1)
PY

echo
echo "[3/4] uploading to $CLOUD_HOST:$CLOUD_DIR"
ssh "$CLOUD_HOST" "mkdir -p /tmp/membrane-daemon-release"
scp manifest.json membrane-daemon-* "$CLOUD_HOST:/tmp/membrane-daemon-release/"
ssh "$CLOUD_HOST" "
    mkdir -p $CLOUD_DIR
    cp /tmp/membrane-daemon-release/* $CLOUD_DIR/
    chown -R www-data:www-data $CLOUD_DIR
    rm -rf /tmp/membrane-daemon-release
    ls -la $CLOUD_DIR/
"

echo
echo "[4/4] smoke test"
curl -fsSL https://mcp.membrane.informationpatterns.com/downloads/manifest.json | python3 -m json.tool

echo
echo "Release $TAG is live."
