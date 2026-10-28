#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="amibidrohi/mint-cua-relay"
API_URL="https://api.github.com/repos/amibidrohi/mint-cua-relay/releases/latest"
RELEASE_URL="https://github.com/amibidrohi/mint-cua-relay/releases/download/"
CURL=(curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2)

for command in curl python3 sha256sum tar mktemp openssl; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done

version="${MINT_CUA_VERSION:-}"
if [[ -z "$version" ]]; then
  release_json="$("${CURL[@]}" "$API_URL")"
  version="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].removeprefix("v"))' <<<"$release_json")"
fi
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid release version: $version" >&2; exit 1; }

asset="mint-cua-relay-$version.tar.gz"
base="${RELEASE_URL}v$version"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/release-public-key.pem" <<'PUBLIC_KEY'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAuc741eWUhMJUTOqXELnR/jvTfmTLKXYtBVFGwVwhPH8=
-----END PUBLIC KEY-----
PUBLIC_KEY
"${CURL[@]}" --output "$tmp/$asset" "$base/$asset"
"${CURL[@]}" --output "$tmp/$asset.sha256" "$base/$asset.sha256"
"${CURL[@]}" --output "$tmp/$asset.sha256.sig" "$base/$asset.sha256.sig"
openssl pkeyutl -verify -pubin -inkey "$tmp/release-public-key.pem" \
  -rawin -in "$tmp/$asset.sha256" -sigfile "$tmp/$asset.sha256.sig" >/dev/null
expected_line="$(cat "$tmp/$asset.sha256")"
[[ "$expected_line" =~ ^[0-9a-fA-F]{64}[[:space:]][[:space:]]mint-cua-relay-${version}\.tar\.gz$ ]] || {
  echo "Malformed checksum file" >&2; exit 1;
}
(cd "$tmp" && sha256sum --check --strict "$asset.sha256")

tar --list --gzip --file "$tmp/$asset" >/dev/null
python3 - "$tmp/$asset" "mint-cua-relay-$version" <<'PY'
import pathlib
import sys
import tarfile

archive, expected_root = sys.argv[1:]
with tarfile.open(archive, "r:gz") as source:
    members = source.getmembers()
    if not members:
        raise SystemExit("Release archive is empty")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if (
            path.is_absolute()
            or not path.parts
            or path.parts[0] != expected_root
            or any(part in ("", ".", "..") for part in path.parts)
            or not (member.isfile() or member.isdir())
        ):
            raise SystemExit(f"Unsafe archive member: {member.name}")
PY
mkdir "$tmp/source"
tar --extract --gzip --file "$tmp/$asset" --directory "$tmp/source" --no-same-owner --no-same-permissions
installer="$tmp/source/mint-cua-relay-$version/scripts/install.sh"
[[ -f "$installer" && ! -L "$installer" ]] || { echo "Release does not contain the exact installer path" >&2; exit 1; }
bash "$installer" --release-version "$version"
