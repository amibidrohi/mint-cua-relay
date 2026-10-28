# Mint CUA Relay

A single-owner Linux Mint X11 relay exposing a constrained subset of `cua-driver`
to a Hermes general plugin through Cloudflare Tunnel and Cloudflare Access. The
origin binds only to `127.0.0.1`; every HTTP request is authenticated before its
body is read or a route is resolved.

## Components and trust boundary

- `cua-driver serve` runs as a hardened systemd user service.
- The FastAPI relay validates Access JWTs and invokes `cua-driver call` with an
  argv array, never a shell.
- GTK 3 or `zenity` asks for local approval and fails closed on GUI errors or
  after 45 seconds.
- A named Cloudflare Tunnel provides outbound-only remote connectivity.
- The Hermes plugin sends service-token headers, validates a bare HTTPS relay
  origin, refuses redirects, and keeps relay capability tokens in process memory
  below model/tool-result context.

## Install

Mint dependencies:

```text
python3 python3-venv python3-gi gir1.2-gtk-3.0 zenity
cloudflared (Cloudflare's signed package/repository)
cua-driver 0.21.x
```

Install the pinned v0.3.1 public release without credentials or `sudo`:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/amibidrohi/mint-cua-relay/v0.3.1/install.sh | bash
```

The downloaded bootstrap is the trust boundary: inspect or obtain that pinned
`install.sh` through a separately trusted channel if GitHub and TLS are not an
acceptable root of trust. The bootstrap embeds the project's Ed25519 public key,
downloads the versioned archive, checksum, and `.sha256.sig`, verifies the
signature over the checksum before checking the archive, rejects unsafe archive
members, and invokes only the exact versioned `scripts/install.sh` path.

For an exact release, set `MINT_CUA_VERSION` on the receiving shell (for example,
`curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/amibidrohi/mint-cua-relay/v0.3.1/install.sh | MINT_CUA_VERSION=0.3.1 bash`).

The installer creates an isolated venv in a versioned release directory under
the resolved `XDG_DATA_HOME`, atomically switches the `current` symlink, adds
`mint-cua` to `${XDG_BIN_HOME:-~/.local/bin}`, generates user units using
resolved XDG paths, installs the plugin under `${HERMES_HOME:-~/.hermes}`, and
forces `relay.env` to mode 0600. Existing relay and Cloudflare configuration is
preserved. Executable and unit paths containing unsafe systemd/template
characters are rejected.

### Update and installation status

```sh
mint-cua update
mint-cua version
mint-cua status
```

`mint-cua update 0.3.1` selects an exact version. Downgrades are rejected unless
explicitly requested with `--allow-downgrade`. Updates use `flock` to prevent
concurrent runs, verify the release checksum, build the new release completely,
and atomically switch `current`. Active relay service instances are restarted
after a successful switch. If `~/.local/bin` is not already on `PATH`, add it
to your shell configuration.

Configure the generated `${XDG_CONFIG_HOME:-~/.config}/mint-cua-relay/relay.env`:

```text
CF_ACCESS_TEAM_DOMAIN=https://TEAM.cloudflareaccess.com
CF_ACCESS_AUD=ACCESS_APPLICATION_AUD_TAG
CF_ACCESS_SERVICE_TOKEN_ID=SERVICE_TOKEN_CLIENT_ID
APPROVAL_TTL_SECONDS=300
MINT_CUA_AUDIT_LOG=/home/YOU/.local/state/mint-cua-relay/audit.jsonl
```

`CF_ACCESS_SERVICE_TOKEN_ID` must exactly match the Access JWT `common_name`.
The relay also requires JWT `type=app`, RS256, exact issuer/audience, expiry,
issue time, and subject.

Create `~/.config/cloudflared/config.yml` with Cloudflare tooling:

```yaml
tunnel: TUNNEL_UUID
credentials-file: /home/YOU/.cloudflared/TUNNEL_UUID.json
ingress:
  - hostname: cua.example.com
    service: http://127.0.0.1:8765
  - service: http_status:404
```

In Cloudflare Zero Trust, create a self-hosted Access application for exactly the
relay hostname and a Service Auth policy including only the Hermes service
token. Do not add Bypass or Everyone policies.

Store client settings and credentials only in the active Hermes profile `.env`:

```text
MINT_CUA_RELAY_URL=https://cua.example.com
CF_ACCESS_CLIENT_ID=...
CF_ACCESS_CLIENT_SECRET=...
CF_ACCESS_SERVICE_TOKEN_ID=...
```

Then:

```sh
systemctl --user enable --now cua-driver-relay mint-cua-relay mint-cua-cloudflared
systemctl --user status cua-driver-relay mint-cua-relay mint-cua-cloudflared
hermes plugins enable mint-cua-remote
hermes plugins validate mint-cua-remote
hermes plugins doctor mint-cua-remote
```

Restart Hermes after enabling the plugin. If the approval dialog cannot reach
the graphical session:

```sh
systemctl --user import-environment DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS
systemctl --user restart mint-cua-relay
```

## Security behavior

- Authentication runs before body parsing and enforces the actual streamed body
  size even when `Content-Length` is absent. As a result, unknown routes are also
  authenticated before returning 404. Framework-generated validation errors do
  not imply that an operation executed.
- First use of a normalized Hermes session requires local approval. The relay
  generates a high-entropy capability, stores only its hash, and requires the
  capability on later calls and revoke. The plugin strips it from tool results
  and caches it only in plugin process memory.
- Prompt, action, and revoke share one global operation lock. This prevents
  prompt floods through the relay and ensures revoke cannot return while an
  earlier relay action can still commit. Prompt is capped at 45 seconds, driver
  execution at 30 seconds, and plugin HTTP timeout is 80 seconds.
- Allowed tools are only `health_report`, `list_apps`, `list_windows`,
  `get_window_state`, `click`, `double_click`, `scroll`, `type_text`,
  `press_key`, and `set_value`. Both plugin schemas and relay validation reject
  unknown fields, caller sessions, targets, desktop scope, screenshot output
  paths, unsafe token/path strings, foreground delivery, and unbounded values.
  The relay forces `delivery_mode=background` and never forwards a driver
  session identifier.
- Metadata-only JSONL audit records cover approve, deny, call, revoke, and error.
  The 0600 log contains no capabilities, Access tokens, screenshots, argument
  objects, or typed text. An audit write failure fails operations closed.
- Grants are memory-only, expire in 1–15 minutes, and disappear on restart.

### X11 limitation

X11 does not provide a trustworthy secure attention path. Another process
running as the same desktop user can spoof the consent dialog or synthesize
input to it. Global relay serialization prevents control already granted through
this relay from clicking a new relay prompt, but it **cannot defend against local
same-user malware or another same-user X11 client**. Treat the logged-in account
and all same-user processes as trusted. This is not suitable for a hostile local
multi-tenant desktop.

The cloudflared unit uses `ProtectHome=read-only`: it can read the operator-owned
home configuration and tunnel credential it needs, but cannot write home. The
project does not claim cloudflared is unable to read home.

## Operational limitations

- Mint Cinnamon X11 is the target. Wayland, lock screens, logged-out, SSH-only,
  headless, multi-seat, and greeter control are unsupported.
- Approval covers the constrained tool subset for a session, not each click or
  keystroke. These actions can still be consequential.
- `cua-driver` permission checks remain authoritative; the relay does not bypass
  them or start it unrestricted.
- Browser/CDP, clipboard, app launch/kill, recording/replay, updates,
  configuration, arbitrary files, screenshot file output, and permission
  changes are not exposed. `get_window_state` can return a bounded embedded
  screenshot when explicitly requested.
- There is no HA, cluster rate limiting, multi-user database, or SIEM exporter.
- The plugin requires `session_id` or, for runtime compatibility, `session_key`.
  It deliberately does not fall back to `task_id`.

## Tests

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest
python3 -m compileall -q src hermes-plugin tests
bash -n scripts/install.sh scripts/uninstall.sh
```

Production validation must still be done on a Mint X11 login with harmless
targets: verify Access rejection, JWT pinning, approve/deny, capability reuse and
revoke, timeout behavior, driver guardrails, service restart, and tunnel loss.

## Uninstall

```sh
./scripts/uninstall.sh
```

The uninstaller intentionally preserves relay and cloudflared configuration.
Revoke/delete the service token and tunnel in Cloudflare separately.
