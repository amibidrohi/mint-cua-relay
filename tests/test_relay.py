from __future__ import annotations

import json
import os
import stat
import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch

import jwt
import pytest
from starlette.testclient import TestClient

from mint_cua_relay.approval import ApprovalRequest, prompt
from mint_cua_relay.audit import AuditLog
from mint_cua_relay.driver import ALLOWED_TOOLS, CuaExecutor, DriverError, validate_arguments
from mint_cua_relay.security import AccessJWTVerifier, AuthError, SessionGrants
from mint_cua_relay.server import create_app


class Verifier:
    def verify(self, token):
        if token != "valid":
            raise AuthError("bad assertion")
        return {"sub": "service-token", "common_name": "required-id", "type": "app"}


class Executor:
    def __init__(self, entered: threading.Event | None = None, release: threading.Event | None = None):
        self.calls = []
        self.entered = entered
        self.release = release

    def call(self, tool, arguments):
        self.calls.append((tool, arguments))
        if self.entered:
            self.entered.set()
        if self.release:
            assert self.release.wait(2)
        return {"tool": tool, "arguments": arguments}


def client(tmp_path: Path, approver=lambda request: True, executor=None, auditor=None):
    executor = executor or Executor()
    auditor = auditor or AuditLog(tmp_path / "audit.jsonl")
    app = create_app(Verifier(), executor, approver, SessionGrants(60), auditor=auditor)
    return TestClient(app), executor, auditor


def headers(session="s1", capability=None):
    result = {"Cf-Access-Jwt-Assertion": "valid", "X-Hermes-Session": session}
    if capability:
        result["X-Mint-CUA-Capability"] = capability
    return result


def approved_call(test_client, body, session="s1"):
    response = test_client.post("/v1/call", headers=headers(session), json=body)
    assert response.status_code == 200, response.text
    token = response.json()["capability_token"]
    assert len(token) >= 43
    return token, response


def test_every_route_requires_access_assertion_before_body(tmp_path):
    test_client, _, _ = client(tmp_path)
    assert test_client.get("/v1/health").status_code == 401
    assert test_client.get("/v1/tools").status_code == 401
    response = test_client.post("/v1/call", content=b"{" * 400_000)
    assert response.status_code == 401


def test_actual_streamed_body_limit_without_content_length(tmp_path):
    test_client, executor, _ = client(tmp_path)

    def chunks():
        yield b'{"tool":"type_text","arguments":{"text":"'
        yield b"a" * 300_001
        yield b'"}}'

    response = test_client.post("/v1/call", headers=headers(), content=chunks())
    assert response.status_code == 413
    assert executor.calls == []


def test_first_call_returns_high_entropy_capability_and_later_calls_require_it(tmp_path):
    prompts: list[ApprovalRequest] = []
    test_client, executor, _ = client(tmp_path, lambda request: prompts.append(request) or True)
    body = {"tool": "list_apps", "arguments": {}}
    token, _ = approved_call(test_client, body)

    assert test_client.post("/v1/call", headers=headers(), json=body).status_code == 403
    assert test_client.post("/v1/call", headers=headers(capability="wrong"), json=body).status_code == 403
    response = test_client.post("/v1/call", headers=headers(capability=token), json=body)
    assert response.status_code == 200
    assert "capability_token" not in response.json()
    assert len(prompts) == 1
    assert len(executor.calls) == 2


def test_capability_is_bound_to_identity_and_normalized_session(tmp_path):
    test_client, _, _ = client(tmp_path)
    body = {"tool": "list_windows", "arguments": {}}
    token, _ = approved_call(test_client, body, "s1")
    assert test_client.post("/v1/call", headers=headers("s2", token), json=body).status_code == 403
    assert test_client.post("/v1/call", headers=headers(" s1 ", token), json=body).status_code == 200


def test_denial_and_approver_exception_fail_closed(tmp_path):
    for approver in (lambda request: False, Mock(side_effect=RuntimeError("GUI broke"))):
        test_client, executor, _ = client(tmp_path, approver)
        response = test_client.post(
            "/v1/call", headers=headers(),
            json={"tool": "click", "arguments": {"pid": 10, "window_id": 20, "x": 1, "y": 2}},
        )
        assert response.status_code in {403, 503}
        assert executor.calls == []


def test_non_allowlisted_tool_and_unknown_body_fields_rejected_before_prompt(tmp_path):
    approver = Mock(return_value=True)
    test_client, executor, _ = client(tmp_path, approver)
    assert test_client.post(
        "/v1/call", headers=headers(), json={"tool": "kill_app", "arguments": {"pid": 1}}
    ).status_code == 403
    assert test_client.post(
        "/v1/call", headers=headers(), json={"tool": "list_apps", "arguments": {}, "target": "x"}
    ).status_code == 422
    approver.assert_not_called()
    assert executor.calls == []


@pytest.mark.parametrize("tool", sorted(ALLOWED_TOOLS))
def test_supported_tool_minimal_arguments_validate(tool):
    minimum = {
        "get_window_state": {"pid": 10, "window_id": 20},
        "click": {"pid": 10, "window_id": 20, "x": 1, "y": 2},
        "double_click": {"pid": 10, "window_id": 20, "x": 1, "y": 2},
        "scroll": {"pid": 10, "window_id": 20, "direction": "down"},
        "type_text": {"pid": 10, "window_id": 20, "text": "hello"},
        "press_key": {"pid": 10, "window_id": 20, "key": "enter"},
        "set_value": {"pid": 10, "element_token": "s0001:2", "value": "hello"},
    }.get(tool, {})
    validated = validate_arguments(tool, minimum)
    if tool in {"click", "double_click", "scroll", "type_text", "press_key"}:
        assert validated["delivery_mode"] == "background"
    else:
        assert "delivery_mode" not in validated
    assert "session" not in validated


def test_useful_bounded_read_filters_and_action_tokens_are_supported():
    assert validate_arguments("list_windows", {"pid": 10, "on_screen_only": True})
    state = validate_arguments(
        "get_window_state",
        {"pid": 10, "window_id": 20, "query": "Save", "max_elements": 100},
    )
    assert state["include_screenshot"] is False
    click = validate_arguments(
        "click", {"pid": 10, "element_token": "s0001:2", "snapshot_id": "s1a2b3c4d"}
    )
    assert click["snapshot_id"] == "s1a2b3c4d"
    key = validate_arguments(
        "press_key", {"pid": 10, "window_id": 20, "x": 3, "y": 4, "key": "enter"}
    )
    assert key["x"] == 3 and key["y"] == 4


@pytest.mark.parametrize("tool,extra", [
    ("click", {}),
    ("scroll", {"direction": "down"}),
    ("type_text", {"text": "hello"}),
    ("press_key", {"key": "enter"}),
])
def test_element_token_actions_require_pid_for_linux_driver(tool, extra):
    with pytest.raises(DriverError, match="requires pid"):
        validate_arguments(tool, {"element_token": "s0001:2", **extra})


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("list_windows", {"app": "Calculator"}),
        ("get_window_state", {"pid": 10, "window_id": 20, "screenshot_out_file": "/tmp/x"}),
        ("get_window_state", {"pid": 10, "window_id": 20, "max_image_dimension": 800}),
        ("get_window_state", {"pid": 10, "window_id": 20, "include_accessibility_tree": True}),
        ("click", {"pid": 10, "element_token": "s0001:2", "capture_id": "old"}),
        ("set_value", {"element_token": "s0001:2", "value": "ok", "delivery_mode": "background"}),
    ],
)
def test_relay_schema_matches_cua_driver_021_and_rejects_nonexistent_fields(tool, arguments):
    with pytest.raises(DriverError):
        validate_arguments(tool, arguments)


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("list_apps", {"unknown": 1}),
        ("click", {"x": 1, "y": 2, "screenshot_out_file": "/tmp/x"}),
        ("click", {"x": 1, "y": 2, "session": "caller"}),
        ("click", {"x": 1, "y": 2, "target": "desktop"}),
        ("click", {"x": 1, "y": 2, "scope": "desktop"}),
        ("click", {"x": 1, "y": 2, "delivery_mode": "foreground"}),
        ("type_text", {"text": "x" * 4097}),
        ("press_key", {"key": "x" * 65}),
        ("scroll", {"pid": 1, "window_id": 2, "direction": "down", "amount": 51}),
        ("set_value", {"element_token": "../../unsafe", "value": "x"}),
        ("double_click", {"element_token": "s0001:2"}),
        ("set_value", {"element_token": "s0001:2", "value": "x"}),
    ],
)
def test_tool_argument_allowlists_reject_dangerous_or_unbounded_values(tool, arguments):
    with pytest.raises(DriverError):
        validate_arguments(tool, arguments)


def test_server_revalidates_arguments_before_prompt(tmp_path):
    approver = Mock(return_value=True)
    test_client, executor, _ = client(tmp_path, approver)
    response = test_client.post(
        "/v1/call", headers=headers(), json={"tool": "type_text", "arguments": {"text": "ok", "unknown": 1}}
    )
    assert response.status_code == 400
    approver.assert_not_called()
    assert executor.calls == []


def test_revoke_requires_capability_and_forces_new_prompt(tmp_path):
    prompts = []
    test_client, _, _ = client(tmp_path, lambda request: prompts.append(request) or True)
    body = {"tool": "list_windows", "arguments": {}}
    token, _ = approved_call(test_client, body)
    assert test_client.post("/v1/revoke", headers=headers()).status_code == 403
    assert test_client.post("/v1/revoke", headers=headers(capability=token)).status_code == 200
    approved_call(test_client, body)
    assert len(prompts) == 2


def test_failed_first_action_discards_unreturned_capability_and_can_reprompt(tmp_path):
    class FailOnceExecutor(Executor):
        def call(self, tool, arguments):
            if not self.calls:
                self.calls.append((tool, arguments))
                raise DriverError("failed")
            return super().call(tool, arguments)

    prompts = []
    executor = FailOnceExecutor()
    test_client, _, _ = client(
        tmp_path, lambda request: prompts.append(request) or True, executor=executor
    )
    body = {"tool": "list_apps", "arguments": {}}
    assert test_client.post("/v1/call", headers=headers(), json=body).status_code == 502
    token, _ = approved_call(test_client, body)
    assert token
    assert len(prompts) == 2


def test_revoke_normalizes_and_length_checks_session(tmp_path):
    test_client, _, _ = client(tmp_path)
    body = {"tool": "list_apps", "arguments": {}}
    token, _ = approved_call(test_client, body, "s1")
    assert test_client.post("/v1/revoke", headers=headers(" s1 ", token)).status_code == 200
    assert test_client.post("/v1/revoke", headers=headers("x" * 161, token)).status_code == 400


def test_global_lock_makes_revoke_wait_for_outstanding_action(tmp_path):
    entered, release = threading.Event(), threading.Event()
    executor = Executor()
    test_client, _, _ = client(tmp_path, executor=executor)
    body = {"tool": "list_apps", "arguments": {}}
    initial_token, _ = approved_call(test_client, body)
    executor.entered = entered
    executor.release = release
    call_done = threading.Event()
    revoke_done = threading.Event()

    def do_call():
        test_client.post("/v1/call", headers=headers(capability=initial_token), json=body)
        call_done.set()

    def do_revoke():
        assert entered.wait(1)
        test_client.post("/v1/revoke", headers=headers(capability=initial_token))
        revoke_done.set()

    call_thread = threading.Thread(target=do_call)
    revoke_thread = threading.Thread(target=do_revoke)
    call_thread.start(); revoke_thread.start()
    assert entered.wait(1)
    time.sleep(0.05)
    assert not revoke_done.is_set()
    release.set()
    call_thread.join(2); revoke_thread.join(2)
    assert call_done.is_set() and revoke_done.is_set()


def test_session_grants_expire_and_do_not_store_raw_capability():
    grants = SessionGrants(60)
    token = grants.add("owner", "session", now=100)
    assert grants.allowed("owner", "session", token, now=159)
    assert not grants.allowed("owner", "session", token, now=160)
    assert token not in repr(grants._grants)


def test_executor_uses_validated_background_args_argv_and_30_second_timeout():
    completed = Mock(returncode=0, stdout='{"ok":true}\n', stderr="")
    with patch("subprocess.run", return_value=completed) as run:
        result = CuaExecutor(binary="/driver", socket="/sock").call("list_apps", {})
    assert result == {"ok": True}
    assert run.call_args.args[0] == ["/driver", "call", "list_apps", "{}", "--socket", "/sock"]
    assert run.call_args.kwargs["timeout"] == 30
    assert run.call_args.kwargs["check"] is False


def test_access_jwt_requires_app_type_and_pinned_common_name():
    verifier = AccessJWTVerifier("https://team.example", "aud", "service-token-id")
    key = Mock(key="public")
    verifier.jwks.get_signing_key_from_jwt = Mock(return_value=key)
    base = {"sub": "x", "type": "app", "common_name": "service-token-id"}
    with patch("jwt.decode", return_value=base):
        assert verifier.verify("token") == base
    with patch("jwt.decode", return_value={**base, "type": "user"}):
        with pytest.raises(AuthError):
            verifier.verify("token")
    with patch("jwt.decode", return_value={**base, "common_name": "other"}):
        with pytest.raises(AuthError):
            verifier.verify("token")


def test_access_verifier_env_requires_service_token_id():
    with patch.dict(os.environ, {"CF_ACCESS_TEAM_DOMAIN": "x", "CF_ACCESS_AUD": "y"}, clear=True):
        with pytest.raises(RuntimeError, match="CF_ACCESS_SERVICE_TOKEN_ID"):
            AccessJWTVerifier.from_env()


def test_prompt_fails_closed_on_every_gui_error():
    with patch("mint_cua_relay.approval._gtk", side_effect=RuntimeError("display failed")):
        assert prompt(ApprovalRequest("id", "session", "click")) is False


def test_audit_is_metadata_only_mode_0600_and_has_required_events(tmp_path):
    test_client, _, auditor = client(tmp_path)
    token, _ = approved_call(
        test_client,
        {"tool": "type_text", "arguments": {"pid": 10, "window_id": 20, "text": "TOP SECRET"}},
    )
    test_client.post("/v1/revoke", headers=headers(capability=token))
    raw = auditor.path.read_text()
    events = [json.loads(line) for line in raw.splitlines()]
    assert {event["event"] for event in events} >= {"approve", "call", "revoke"}
    assert "TOP SECRET" not in raw and token not in raw
    assert not any(key in raw for key in ('"arguments"', '"text"', '"token"', '"screenshot"'))
    assert stat.S_IMODE(auditor.path.stat().st_mode) == 0o600


def test_audit_failure_fails_closed_before_execution(tmp_path):
    auditor = Mock()
    auditor.write.side_effect = OSError("disk full")
    test_client, executor, _ = client(tmp_path, auditor=auditor)
    response = test_client.post("/v1/call", headers=headers(), json={"tool": "list_apps", "arguments": {}})
    assert response.status_code == 503
    assert executor.calls == []
