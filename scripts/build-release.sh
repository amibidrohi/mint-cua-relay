#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(python3 - "$ROOT/pyproject.toml" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as source:
    print(tomllib.load(source)["project"]["version"])
PY
)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid project version: $VERSION" >&2; exit 1; }
OUT="${1:-$ROOT/dist}"
ASSET="mint-cua-relay-$VERSION.tar.gz"
PREFIX="mint-cua-relay-$VERSION"
mkdir -p "$OUT"
rm -f "$OUT/$ASSET" "$OUT/$ASSET.sha256" "$OUT/$ASSET.sha256.sig"
tar --create --gzip --file "$OUT/$ASSET" --directory "$ROOT" \
  --sort=name --owner=0 --group=0 --numeric-owner \
  --exclude='*/__pycache__' --exclude='*.pyc' --exclude='*.egg-info' \
  --transform="s,^,$PREFIX/," \
  README.md install.sh pyproject.toml requirements.lock release-public-key.pem \
  src hermes-plugin packaging scripts
(cd "$OUT" && sha256sum "$ASSET" > "$ASSET.sha256")
echo "$OUT/$ASSET"
echo "$OUT/$ASSET.sha256"
if [[ -n "${MINT_CUA_SIGNING_KEY:-}" ]]; then
  [[ -f "$MINT_CUA_SIGNING_KEY" ]] || { echo "MINT_CUA_SIGNING_KEY is not a file" >&2; exit 1; }
  openssl pkeyutl -sign -inkey "$MINT_CUA_SIGNING_KEY" -rawin \
    -in "$OUT/$ASSET.sha256" -out "$OUT/$ASSET.sha256.sig"
  echo "$OUT/$ASSET.sha256.sig"
fi
