#!/usr/bin/env bash
set -euo pipefail

APP_HOME="${MINT_CUA_INSTALL_ROOT:-${XDG_DATA_HOME:-$HOME/.local/share}/mint-cua-relay}"
CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}/mint-cua-relay"
UNIT_HOME="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
BIN_HOME="${XDG_BIN_HOME:-$HOME/.local/bin}"
HERMES_ROOT="${HERMES_HOME:-$HOME/.hermes}"

APP_HOME="$(realpath -m -- "$APP_HOME")"
HOME_REAL="$(realpath -m -- "$HOME")"
case "$APP_HOME" in
  /|"$HOME_REAL") printf 'Refusing unsafe install root: %s\n' "$APP_HOME" >&2; exit 1 ;;
esac
[[ -f "$APP_HOME/.mint-cua-install-root" ]] || {
  printf 'Refusing unsafe install root without Mint CUA marker: %s\n' "$APP_HOME" >&2; exit 1;
}
[[ "$(cat "$APP_HOME/.mint-cua-install-root")" == "mint-cua-relay" ]] || {
  printf 'Refusing unsafe install root with invalid marker: %s\n' "$APP_HOME" >&2; exit 1;
}

systemctl --user disable --now mint-cua-cloudflared.service mint-cua-relay.service cua-driver-relay.service 2>/dev/null || true
rm -f "$UNIT_HOME/mint-cua-cloudflared.service" "$UNIT_HOME/mint-cua-relay.service" "$UNIT_HOME/cua-driver-relay.service"
rm -f "$BIN_HOME/mint-cua"
rm -rf "$APP_HOME" "$HERMES_ROOT/plugins/mint-cua-remote"
systemctl --user daemon-reload

printf 'Removed program, units, and Hermes plugin.\n'
printf 'Preserved %s and ~/.config/cloudflared (may contain operator-owned credentials).\n' "$CONFIG_HOME"
