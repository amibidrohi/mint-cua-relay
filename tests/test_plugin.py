from __future__ import annotations

import importlib.util
import json
import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest


PLUGIN_PATH = Path(__file__).parents[1] / "hermes-plugin" / "__init__.py"
spec = importlib.util.spec_from_file_location("mint_cua_plugin", PLUGIN_PATH)
plugin = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(plugin)


class Context:
    def __init__(self):
        self.tools = {}

    def register_tool(self, *, name, handler, schema, **kwargs):
        self.tools[name] = (handler, schema)


def response(payload):
    result = Mock()
    result.read.return_value = json.dumps(payload).encode()
    result.__enter__ = Mock(return_value=result)
    result.__exit__ = Mock(return_value=False)
    return result


def env(url="https://cua.example.com"):
    return {
        "MINT_CUA_RELAY_URL": url,
        "CF_ACCESS_CLIENT_ID": "client-id",
        "CF_ACCESS_CLIENT_SECRET": "client-secret",
    }


def setup_function():
    plugin._CAPABILITIES.clear()


def test_plugin_registers_call_and_end_session_tools_with_per_tool_schemas():
    ctx = Context()
    plugin.register(ctx)
    assert set(ctx.tools) == {"remote_cua_call", "remote_cua_end_session"}
    schema = ctx.tools["remote_cua_call"][1]
    variants = schema["parameters"]["oneOf"]
    assert {item["properties"]["tool"]["const"] for item in variants} == set(plugin.TOOLS)
    for item in variants:
        assert item["additionalProperties"] is False
        assert item["properties"]["arguments"]["additionalProperties"] is False
    state = next(item for item in variants if item["properties"]["tool"]["const"] == "get_window_state")
    assert set(state["properties"]["arguments"]["required"]) == {"pid", "window_id"}
    click = next(item for item in variants if item["properties"]["tool"]["const"] == "click")
    assert "pid" in click["properties"]["arguments"]["properties"]
    assert "element_token" in click["properties"]["arguments"]["properties"]
    for name in ("double_click", "set_value"):
        variant = next(item for item in variants if item["properties"]["tool"]["const"] == name)
        assert "pid" in variant["properties"]["arguments"]["required"]
    double_click = next(item for item in variants if item["properties"]["tool"]["const"] == "double_click")
    assert "button" not in double_click["properties"]["arguments"]["properties"]
    for name in ("click", "scroll", "type_text", "press_key"):
        variant = next(item for item in variants if item["properties"]["tool"]["const"] == name)
        assert "pid" in variant["properties"]["arguments"]["required"]


def test_capability_is_cached_below_model_context_sent_later_and_removed_on_revoke():
    capability = "s" * 43
    first = response({"ok": True, "result": {}, "capability_token": capability})
    second = response({"ok": True, "result": {}})
    revoked = response({"ok": True})
    with patch.dict(plugin.os.environ, env(), clear=False), patch.object(
        plugin._OPENER, "open", side_effect=[first, second, revoked]
    ) as open_url:
        visible = json.loads(plugin._handle({"tool": "list_apps", "arguments": {}}, session_id="session-123"))
        plugin._handle({"tool": "list_apps", "arguments": {}}, session_id="session-123")
        plugin._end_session({}, session_id="session-123")

    assert "capability_token" not in visible
    requests = [call.args[0] for call in open_url.call_args_list]
    assert "X-mint-cua-capability" not in requests[0].headers
    assert requests[1].headers["X-mint-cua-capability"] == capability
    assert requests[2].headers["X-mint-cua-capability"] == capability
    assert "session-123" not in plugin._CAPABILITIES


def test_same_session_requests_serialize_until_capability_is_cached():
    first_entered = threading.Event()
    release_first = threading.Event()
    requests = []

    def open_request(request, timeout):
        del timeout
        requests.append(request)
        if len(requests) == 1:
            first_entered.set()
            assert release_first.wait(2)
            return response({"ok": True, "result": {}, "capability_token": "s" * 43})
        return response({"ok": True, "result": {}})

    results = []
    with patch.dict(plugin.os.environ, env(), clear=False), patch.object(
        plugin._OPENER, "open", side_effect=open_request
    ):
        first = threading.Thread(
            target=lambda: results.append(plugin._handle(
                {"tool": "list_apps", "arguments": {}}, session_id="session-123"
            ))
        )
        second = threading.Thread(
            target=lambda: results.append(plugin._handle(
                {"tool": "list_apps", "arguments": {}}, session_id="session-123"
            ))
        )
        first.start()
        assert first_entered.wait(1)
        second.start()
        time.sleep(0.05)
        assert len(requests) == 1
        release_first.set()
        first.join(2)
        second.join(2)

    assert len(requests) == 2
    assert requests[1].headers["X-mint-cua-capability"] == "s" * 43


def test_session_id_has_priority_session_key_is_fallback_and_task_id_is_rejected():
    assert plugin._session({"session_id": "primary", "session_key": "secondary"}) == "primary"
    assert plugin._session({"session_key": "secondary"}) == "secondary"
    with pytest.raises(RuntimeError):
        plugin._session({"task_id": "unsafe-fallback"})
    with pytest.raises(RuntimeError):
        plugin._session({"session_id": "x" * 161})


@pytest.mark.parametrize(
    "url",
    [
        "http://cua.example.com",
        "https://user:pass@cua.example.com",
        "https://cua.example.com/#fragment",
        "https://cua.example.com/?query=1",
        "https://cua.example.com/path",
    ],
)
def test_relay_url_must_be_bare_https_origin(url):
    with patch.dict(plugin.os.environ, env(url), clear=False):
        with pytest.raises(RuntimeError):
            plugin._relay_base()


def test_redirects_are_disabled():
    assert any(type(handler) is plugin.NoRedirect for handler in plugin._OPENER.handlers)
    redirect = plugin.NoRedirect()
    assert redirect.redirect_request(Mock(), Mock(), 302, "Found", {}, "https://evil.example") is None


def test_plugin_timeout_exceeds_prompt_plus_driver_maximum():
    assert plugin.REQUEST_TIMEOUT > 45 + 30


def test_end_session_posts_to_revoke_for_current_session():
    with patch.dict(plugin.os.environ, env(), clear=False), patch.object(
        plugin._OPENER, "open", return_value=response({"ok": True})
    ) as open_url:
        plugin._CAPABILITIES["session-123"] = "cap"
        result = plugin._end_session({}, session_id="session-123")
    request = open_url.call_args.args[0]
    assert request.full_url == "https://cua.example.com/v1/revoke"
    assert request.method == "POST"
    assert request.headers["X-hermes-session"] == "session-123"
    assert result == '{"ok": true}'
