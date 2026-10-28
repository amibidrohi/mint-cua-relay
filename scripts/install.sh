#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(python3 - "$ROOT/pyproject.toml" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as source:
    print(tomllib.load(source)["project"]["version"])
PY
)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid package version: $VERSION" >&2; exit 1; }
if [[ "${1:-}" == "--release-version" ]]; then
  [[ $# -eq 2 ]] || { echo "Usage: $0 [--release-version VERSION]" >&2; exit 2; }
  [[ "$2" == "$VERSION" ]] || { echo "Package version is $VERSION, not $2" >&2; exit 1; }
elif [[ $# -ne 0 ]]; then
  echo "Usage: $0 [--release-version VERSION]" >&2; exit 2
fi

APP_HOME="${MINT_CUA_INSTALL_ROOT:-${XDG_DATA_HOME:-$HOME/.local/share}/mint-cua-relay}"
RELEASES_HOME="$APP_HOME/releases"
RELEASE_HOME="$RELEASES_HOME/$VERSION"
CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}/mint-cua-relay"
STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}/mint-cua-relay"
UNIT_HOME="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
BIN_HOME="${XDG_BIN_HOME:-$HOME/.local/bin}"
HERMES_ROOT="${HERMES_HOME:-$HOME/.hermes}"
CUA_DRIVER="${CUA_DRIVER_BIN:-$(command -v cua-driver || true)}"
if [[ -z "$CUA_DRIVER" ]]; then
  for candidate in "${HERMES_HOME:-$HOME/.hermes}"/tools/cua-driver-*/cua-driver \
                   "$HOME"/.hermes/tools/cua-driver-*/cua-driver; do
    [[ -x "$candidate" ]] && CUA_DRIVER="$candidate"
  done
fi
CLOUDFLARED="${CLOUDFLARED_BIN:-$(command -v cloudflared || true)}"

validate_executable() {
  local name="$1" path="$2" resolved
  [[ "$path" =~ ^/[A-Za-z0-9._/+:-]+$ ]] || {
    printf 'Unsafe %s executable path: %q\n' "$name" "$path" >&2; exit 1;
  }
  resolved="$(realpath -e -- "$path")"
  [[ "$resolved" =~ ^/[A-Za-z0-9._/+:-]+$ && -f "$resolved" && -x "$resolved" ]] || {
    printf 'Unsafe %s resolved executable path: %q\n' "$name" "$resolved" >&2; exit 1;
  }
  printf '%s' "$resolved"
}

validate_unit_path() {
  [[ "$2" =~ ^/[A-Za-z0-9._/+:-]+$ ]] || {
    printf 'Unsafe %s path for systemd unit: %q\n' "$1" "$2" >&2; exit 1;
  }
}

render_unit() {
  local source="$1" destination="$2"
  shift 2
  python3 - "$source" "$destination" "$@" <<'PY'
import os
import sys
from pathlib import Path
source, destination, *pairs = sys.argv[1:]
text = Path(source).read_text()
for pair in pairs:
    key, value = pair.split("=", 1)
    text = text.replace(f"__{key}__", value)
if "__" in text:
    raise SystemExit(f"unresolved unit placeholder in {source}")
fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
with os.fdopen(fd, "w") as output:
    output.write(text)
os.chmod(destination, 0o644)
PY
}

[[ -n "$CUA_DRIVER" ]] || { echo "cua-driver is required" >&2; exit 1; }
[[ -n "$CLOUDFLARED" ]] || { echo "cloudflared is required" >&2; exit 1; }
for command in python3 flock systemctl; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done
python3 -m venv --help >/dev/null || { echo "python3-venv is required" >&2; exit 1; }
CUA_DRIVER="$(validate_executable cua-driver "$CUA_DRIVER")"
CLOUDFLARED="$(validate_executable cloudflared "$CLOUDFLARED")"
validate_unit_path APP_HOME "$APP_HOME"
validate_unit_path CONFIG_HOME "$CONFIG_HOME"
validate_unit_path STATE_HOME "$STATE_HOME"
validate_unit_path UNIT_HOME "$UNIT_HOME"

install -d -m 700 "$APP_HOME" "$RELEASES_HOME" "$CONFIG_HOME" "$STATE_HOME" "$UNIT_HOME" \
  "$HERMES_ROOT/plugins/mint-cua-remote" "$HOME/.cache/cua-driver"
install -d -m 755 "$BIN_HOME"
printf '%s\n' 'mint-cua-relay' > "$APP_HOME/.mint-cua-install-root"
chmod 600 "$APP_HOME/.mint-cua-install-root"
exec 9>"$APP_HOME/.install.lock"
flock -n 9 || { echo "Another Mint CUA installation is running" >&2; exit 1; }

previous_target="$(readlink -f -- "$APP_HOME/current" 2>/dev/null || true)"
shared_backup="$APP_HOME/.shared-backup-$$"
install -d -m 700 "$shared_backup"
backup_one() { [[ ! -e "$1" ]] || { cp -a -- "$1" "$shared_backup/$2"; : > "$shared_backup/$2.existed"; }; }
backup_one "$BIN_HOME/mint-cua" mint-cua
backup_one "$UNIT_HOME/mint-cua-relay.service" mint-cua-relay.service
backup_one "$UNIT_HOME/mint-cua-cloudflared.service" mint-cua-cloudflared.service
backup_one "$UNIT_HOME/cua-driver-relay.service" cua-driver-relay.service
backup_one "$HERMES_ROOT/plugins/mint-cua-remote" plugin
restore_one() {
  rm -rf -- "$1"
  [[ ! -f "$shared_backup/$2.existed" ]] || cp -a -- "$shared_backup/$2" "$1"
}
restore_shared_files() {
  restore_one "$BIN_HOME/mint-cua" mint-cua
  restore_one "$UNIT_HOME/mint-cua-relay.service" mint-cua-relay.service
  restore_one "$UNIT_HOME/mint-cua-cloudflared.service" mint-cua-cloudflared.service
  restore_one "$UNIT_HOME/cua-driver-relay.service" cua-driver-relay.service
  restore_one "$HERMES_ROOT/plugins/mint-cua-remote" plugin
  systemctl --user daemon-reload
}
was_active=0
if systemctl --user is-active --quiet mint-cua-relay.service; then
  was_active=1
fi

if [[ ! -d "$RELEASE_HOME" ]]; then
  staging="$RELEASES_HOME/.install-$VERSION-$$"
  trap 'rm -rf "${staging:-}" "$APP_HOME/.current.new" "$APP_HOME/.current.rollback"' EXIT
  python3 -m venv "$staging/venv"
  "$staging/venv/bin/python" -m pip install --disable-pip-version-check \
    --require-hashes --only-binary=:all: -r "$ROOT/requirements.lock"
  "$staging/venv/bin/python" -m pip install --disable-pip-version-check \
    --no-deps --no-build-isolation "$ROOT"
  printf '%s\n' "$VERSION" > "$staging/VERSION"
  install -m 755 "$ROOT/install.sh" "$staging/install.sh"
  mv -- "$staging" "$RELEASE_HOME"
fi

install -m 755 "$ROOT/scripts/mint-cua" "$BIN_HOME/mint-cua"
render_unit "$ROOT/packaging/mint-cua-relay.service.in" \
  "$UNIT_HOME/mint-cua-relay.service" \
  "APP_HOME=$APP_HOME" "CONFIG_HOME=$CONFIG_HOME" "STATE_HOME=$STATE_HOME"
render_unit "$ROOT/packaging/mint-cua-cloudflared.service.in" \
  "$UNIT_HOME/mint-cua-cloudflared.service" "CLOUDFLARED=$CLOUDFLARED"
render_unit "$ROOT/packaging/cua-driver-relay.service.in" \
  "$UNIT_HOME/cua-driver-relay.service" "CUA_DRIVER=$CUA_DRIVER"
install -m 644 "$ROOT/hermes-plugin/plugin.yaml" "$HERMES_ROOT/plugins/mint-cua-remote/"
install -m 644 "$ROOT/hermes-plugin/__init__.py" "$HERMES_ROOT/plugins/mint-cua-remote/"

if [[ ! -e "$CONFIG_HOME/relay.env" ]]; then
  install -m 600 /dev/null "$CONFIG_HOME/relay.env"
  printf '%s\n' \
    'CF_ACCESS_TEAM_DOMAIN=https://YOUR-TEAM.cloudflareaccess.com' \
    'CF_ACCESS_AUD=YOUR_APPLICATION_AUD_TAG' \
    'CF_ACCESS_SERVICE_TOKEN_ID=YOUR_SERVICE_TOKEN_CLIENT_ID' \
    'APPROVAL_TTL_SECONDS=300' \
    "MINT_CUA_AUDIT_LOG=$STATE_HOME/audit.jsonl" \
    > "$CONFIG_HOME/relay.env"
fi
chmod 600 "$CONFIG_HOME/relay.env"
systemctl --user daemon-reload

# Activation is deliberately last: every release file and shared resource is ready.
rm -f "$APP_HOME/.current.new"
ln -s "$RELEASE_HOME" "$APP_HOME/.current.new"
mv -Tf "$APP_HOME/.current.new" "$APP_HOME/current"
if [[ "$was_active" -eq 1 ]]; then
  activation_failed=0
  systemctl --user restart mint-cua-relay.service || activation_failed=1
  systemctl --user is-active --quiet mint-cua-relay.service || activation_failed=1
  if [[ "$activation_failed" -eq 1 ]]; then
    echo "Activation health check failed; rolling back" >&2
    if [[ -n "$previous_target" && -d "$previous_target" ]]; then
      rm -f "$APP_HOME/.current.rollback"
      ln -s "$previous_target" "$APP_HOME/.current.rollback"
      mv -Tf "$APP_HOME/.current.rollback" "$APP_HOME/current"
      restore_shared_files
      systemctl --user restart mint-cua-relay.service || {
        echo "Rollback failed: previous service did not restart" >&2
        exit 1
      }
      systemctl --user is-active --quiet mint-cua-relay.service || {
        echo "Rollback failed: previous service is not active" >&2
        exit 1
      }
    else
      rm -f "$APP_HOME/current"
      restore_shared_files
    fi
    exit 1
  fi
fi
rm -rf -- "$shared_backup"
cat <<EOF
Installed Mint CUA Relay $VERSION.
Management command: $BIN_HOME/mint-cua
Configuration preserved at: $CONFIG_HOME/relay.env
Before first enable, configure relay.env and Cloudflare Tunnel, then run:
  systemctl --user enable --now cua-driver-relay mint-cua-relay mint-cua-cloudflared
  hermes plugins enable mint-cua-remote
EOF
