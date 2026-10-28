"""Hermes general plugin client for Mint CUA Relay."""
from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request

TOOLS = [
    "health_report", "list_apps", "list_windows", "get_window_state",
    "click", "double_click", "scroll", "type_text", "press_key", "set_value",
]
REQUEST_TIMEOUT = 80
_CAPABILITIES: dict[str, str] = {}
_CAPABILITY_LOCK = threading.Lock()
_REQUEST_LOCK = threading.Lock()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(NoRedirect())

EMPTY_ARGS = {"type": "object", "properties": {}, "additionalProperties": False}
TOKEN = {"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[A-Za-z0-9_.:-]+$"}
PID = {"type": "integer", "minimum": 1, "maximum": 2147483647}
WINDOW_ID = {"type": "integer", "minimum": 1}
COORD = {"type": "integer", "minimum": -100000, "maximum": 100000}
WINDOW_PROPERTIES = {
    "pid": PID,
    "window_id": WINDOW_ID,
    "element_index": {"type": "integer", "minimum": 0, "maximum": 1000000},
    "element_token": TOKEN,
    "snapshot_id": {**TOKEN, "maxLength": 9},
}
CLICK_PROPERTIES = {
    **WINDOW_PROPERTIES,
    "x": COORD, "y": COORD,
    "button": {"type": "string", "enum": ["left", "middle", "right"]},
    "from_zoom": {"type": "boolean"},
}
DOUBLE_CLICK_PROPERTIES = {
    key: value for key, value in CLICK_PROPERTIES.items() if key != "button"
}
ARGUMENT_SCHEMAS = {
    "health_report": EMPTY_ARGS,
    "list_apps": EMPTY_ARGS,
    "list_windows": {
        "type": "object",
        "properties": {
            "pid": PID,
            "on_screen_only": {"type": "boolean"},
        },
        "additionalProperties": False,
    },
    "get_window_state": {
        "type": "object",
        "properties": {
            "pid": PID, "window_id": WINDOW_ID,
            "query": {"type": "string", "maxLength": 512},
            "max_elements": {"type": "integer", "minimum": 1, "maximum": 500},
            "max_depth": {"type": "integer", "minimum": 1, "maximum": 25},
            "include_screenshot": {"type": "boolean"},
        },
        "required": ["pid", "window_id"], "additionalProperties": False,
    },
    "click": {
        "type": "object",
        "properties": {
            **CLICK_PROPERTIES,
            "count": {"type": "integer", "minimum": 1, "maximum": 3},
            "modifier": {
                "type": "array", "maxItems": 4, "uniqueItems": True,
                "items": {"type": "string", "enum": ["ctrl", "shift", "alt", "super"]},
            },
        },
        "required": ["pid"],
        "anyOf": [
            {"required": ["pid", "window_id", "x", "y"]},
            {"required": ["element_token"]},
        ],
        "additionalProperties": False,
    },
    "double_click": {
        "type": "object", "properties": DOUBLE_CLICK_PROPERTIES,
        "required": ["pid"],
        "anyOf": [
            {"required": ["pid", "window_id", "x", "y"]},
            {"required": ["element_token"]},
        ],
        "additionalProperties": False,
    },
    "scroll": {
        "type": "object",
        "properties": {
            **WINDOW_PROPERTIES, "x": COORD, "y": COORD,
            "direction": {"type": "string", "enum": ["up", "down", "left", "right"]},
            "amount": {"type": "integer", "minimum": 1, "maximum": 50},
            "by": {"type": "string", "enum": ["line", "page"]},
        },
        "required": ["pid", "direction"],
        "additionalProperties": False,
    },
    "type_text": {
        "type": "object",
        "properties": {
            **WINDOW_PROPERTIES, "x": COORD, "y": COORD,
            "text": {"type": "string", "minLength": 1, "maxLength": 4096},
        },
        "required": ["pid", "text"],
        "additionalProperties": False,
    },
    "press_key": {
        "type": "object",
        "properties": {
            **WINDOW_PROPERTIES, "x": COORD, "y": COORD,
            "key": {"type": "string", "minLength": 1, "maxLength": 64},
            "modifiers": {
                "type": "array", "maxItems": 4, "uniqueItems": True,
                "items": {"type": "string", "enum": ["ctrl", "shift", "alt", "super"]},
            },
        },
        "required": ["pid", "key"],
        "additionalProperties": False,
    },
    "set_value": {
        "type": "object",
        "properties": {
            **WINDOW_PROPERTIES,
            "value": {"type": "string", "minLength": 1, "maxLength": 4096},
        },
        "required": ["pid", "element_token", "value"], "additionalProperties": False,
    },
}

SCHEMA = {
    "name": "remote_cua_call",
    "description": (
        "Call one constrained cua-driver tool on the user's remote Linux desktop. "
        "The first call in each Hermes session requires local desktop approval."
    ),
    "parameters": {
        "type": "object",
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "tool": {"const": tool},
                    "arguments": ARGUMENT_SCHEMAS[tool],
                },
                "required": ["tool", "arguments"],
                "additionalProperties": False,
            }
            for tool in TOOLS
        ],
    },
}

END_SCHEMA = {
    "name": "remote_cua_end_session",
    "description": "Immediately revoke this Hermes session's remote desktop approval.",
    "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
}


def _session(kwargs: dict) -> str:
    for key in ("session_id", "session_key"):
        value = kwargs.get(key)
        if value:
            session = str(value).strip()
            if not session or len(session) > 160 or any(
                ord(char) < 0x20 or ord(char) == 0x7f for char in session
            ):
                raise RuntimeError("Hermes provided an invalid session identifier")
            return session
    raise RuntimeError("Hermes did not provide a session identifier")


def _relay_base() -> str:
    raw = os.environ["MINT_CUA_RELAY_URL"]
    parsed = urllib.parse.urlsplit(raw)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
        or parsed.password is not None or parsed.fragment or parsed.query
        or parsed.path not in {"", "/"}
    ):
        raise RuntimeError("MINT_CUA_RELAY_URL must be a bare HTTPS origin without credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError("MINT_CUA_RELAY_URL has an invalid port") from exc
    host = parsed.hostname
    if any(ord(char) < 0x21 or ord(char) == 0x7f for char in raw):
        raise RuntimeError("MINT_CUA_RELAY_URL contains unsafe characters")
    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority += f":{port}"
    return f"https://{authority}"


def _request_locked(path: str, body: bytes, kwargs: dict) -> str:
    session = _session(kwargs)
    headers = {
        "Content-Type": "application/json",
        "CF-Access-Client-Id": os.environ["CF_ACCESS_CLIENT_ID"],
        "CF-Access-Client-Secret": os.environ["CF_ACCESS_CLIENT_SECRET"],
        "X-Hermes-Session": session,
    }
    with _CAPABILITY_LOCK:
        capability = _CAPABILITIES.get(session)
    if capability:
        headers["X-Mint-CUA-Capability"] = capability
    request = urllib.request.Request(
        _relay_base() + path, data=body, method="POST", headers=headers,
    )
    try:
        with _OPENER.open(request, timeout=REQUEST_TIMEOUT) as response:
            raw = response.read(1_000_001)
            if len(raw) > 1_000_000:
                raise RuntimeError("relay response too large")
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace")
        if path == "/v1/call" and exc.code == 403:
            with _CAPABILITY_LOCK:
                _CAPABILITIES.pop(session, None)
        return json.dumps({"ok": False, "status": exc.code, "error": detail})
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return json.dumps({"ok": False, "error": f"relay unavailable: {exc}"})

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return json.dumps({"ok": False, "error": "invalid relay response"})
    token = payload.pop("capability_token", None)
    if token is not None:
        if not isinstance(token, str) or not 43 <= len(token) <= 128:
            return json.dumps({"ok": False, "error": "invalid relay capability"})
        with _CAPABILITY_LOCK:
            _CAPABILITIES[session] = token
    if path == "/v1/revoke" and payload.get("ok") is True:
        with _CAPABILITY_LOCK:
            _CAPABILITIES.pop(session, None)
    return json.dumps(payload)


def _request(path: str, body: bytes, kwargs: dict) -> str:
    # The first response mints the capability used by later calls. Serializing
    # requests prevents a concurrent 403 from deleting a freshly cached token.
    with _REQUEST_LOCK:
        return _request_locked(path, body, kwargs)


def _handle(params, **kwargs):
    body = json.dumps({"tool": params["tool"], "arguments": params["arguments"]}).encode()
    return _request("/v1/call", body, kwargs)


def _end_session(params, **kwargs):
    del params
    return _request("/v1/revoke", b"{}", kwargs)


def register(ctx):
    ctx.register_tool(
        name="remote_cua_call", toolset="mint_cua_remote", schema=SCHEMA, handler=_handle,
    )
    ctx.register_tool(
        name="remote_cua_end_session", toolset="mint_cua_remote",
        schema=END_SCHEMA, handler=_end_session,
    )
