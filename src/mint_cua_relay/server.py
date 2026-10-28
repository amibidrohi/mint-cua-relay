from __future__ import annotations

import json
import os
import queue
import threading
from typing import Any, Callable

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .approval import PROMPT_TIMEOUT_SECONDS, ApprovalRequest, prompt
from .audit import AuditLog
from .driver import ALLOWED_TOOLS, CuaExecutor, DriverError, validate_arguments
from .security import AccessJWTVerifier, AuthError, SessionGrants

MAX_BODY_BYTES = 300_000


class Call(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str = Field(min_length=1, max_length=80)
    arguments: dict[str, Any] = Field(default_factory=dict)


def _normalize_session(value: str) -> str:
    session = value.strip()
    if not session or len(session) > 160 or any(ord(char) < 0x20 or ord(char) == 0x7f for char in session):
        raise HTTPException(status_code=400, detail="valid X-Hermes-Session required")
    return session


def _approval_with_timeout(approver: Callable[[ApprovalRequest], bool], request: ApprovalRequest) -> bool:
    results: queue.Queue[bool] = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            result = bool(approver(request))
        except Exception:
            result = False
        try:
            results.put_nowait(result)
        except queue.Full:
            pass

    thread = threading.Thread(target=run, name="mint-cua-approval", daemon=True)
    thread.start()
    try:
        return results.get(timeout=PROMPT_TIMEOUT_SECONDS)
    except queue.Empty:
        return False


class SecurityMiddleware:
    """Authenticate before reading and cap bytes at the ASGI receive boundary."""

    def __init__(self, app, verifier: Any, auditor: AuditLog) -> None:
        self.app = app
        self.verifier = verifier
        self.auditor = auditor

    async def _respond(self, send, status: int, detail: str) -> None:
        body = json.dumps({"detail": detail}).encode()
        await send({
            "type": "http.response.start", "status": status,
            "headers": [(b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        assertion = headers.get(b"cf-access-jwt-assertion", b"").decode("latin-1")
        try:
            claims = self.verifier.verify(assertion)
            identity = str(claims.get("common_name") or claims["sub"])
        except (AuthError, KeyError) as exc:
            try:
                self.auditor.write("error", outcome="authentication")
            except OSError:
                await self._respond(send, 503, "audit unavailable")
                return
            await self._respond(send, 401, str(exc))
            return

        scope.setdefault("state", {})["identity"] = identity
        # Read only after authentication, stop at the byte cap, then replay the
        # bounded body to FastAPI. This enforces bytes received rather than a
        # caller-controlled Content-Length value and runs before JSON parsing.
        chunks: list[bytes] = []
        seen = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            seen += len(chunk)
            if seen > MAX_BODY_BYTES:
                try:
                    self.auditor.write("error", identity=identity, outcome="body_too_large")
                except OSError:
                    await self._respond(send, 503, "audit unavailable")
                    return
                await self._respond(send, 413, "request too large")
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        replayed = False

        async def bounded_receive():
            nonlocal replayed
            if replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": b"".join(chunks), "more_body": False}

        await self.app(scope, bounded_receive, send)


def create_app(
    verifier: Any | None = None,
    executor: Any | None = None,
    approver: Callable[[ApprovalRequest], bool] = prompt,
    grants: SessionGrants | None = None,
    *,
    auditor: AuditLog | None = None,
) -> FastAPI:
    auth = verifier or AccessJWTVerifier.from_env()
    driver = executor or CuaExecutor()
    session_grants = grants or SessionGrants(int(os.getenv("APPROVAL_TTL_SECONDS", "300")))
    audit = auditor or AuditLog()
    operation_lock = threading.Lock()
    app = FastAPI(title="Mint CUA Relay", docs_url=None, redoc_url=None, openapi_url=None)

    def audit_or_fail(event: str, **metadata: str) -> None:
        try:
            audit.write(event, **metadata)
        except OSError as exc:
            raise HTTPException(status_code=503, detail="audit unavailable") from exc

    @app.get("/v1/health")
    def health():
        return {"ok": True}

    @app.get("/v1/tools")
    def tools():
        return {"tools": sorted(ALLOWED_TOOLS)}

    @app.post("/v1/call")
    def call(
        request: Request,
        body: Call,
        x_hermes_session: str = Header(default=""),
        x_mint_cua_capability: str = Header(default=""),
    ):
        identity = request.state.identity
        session = _normalize_session(x_hermes_session)
        if body.tool not in ALLOWED_TOOLS:
            audit_or_fail("error", identity=identity, session=session, tool=body.tool,
                          outcome="tool_denied")
            raise HTTPException(status_code=403, detail="tool not allowed")
        try:
            safe_arguments = validate_arguments(body.tool, body.arguments)
        except DriverError as exc:
            audit_or_fail("error", identity=identity, session=session, tool=body.tool,
                          outcome="invalid_arguments")
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        with operation_lock:
            new_capability = ""
            approved_now = False
            if session_grants.exists(identity, session):
                if not session_grants.allowed(identity, session, x_mint_cua_capability):
                    audit_or_fail("error", identity=identity, session=session, tool=body.tool,
                                  outcome="capability_denied")
                    raise HTTPException(status_code=403, detail="valid capability required")
            else:
                if x_mint_cua_capability:
                    audit_or_fail("error", identity=identity, session=session, tool=body.tool,
                                  outcome="stale_capability")
                    raise HTTPException(status_code=403, detail="capability expired or revoked")
                approved = _approval_with_timeout(
                    approver, ApprovalRequest(identity, session, body.tool)
                )
                if not approved:
                    audit_or_fail("deny", identity=identity, session=session, tool=body.tool)
                    raise HTTPException(status_code=403, detail="local approval denied or unavailable")
                audit_or_fail("approve", identity=identity, session=session, tool=body.tool)
                approved_now = True

            audit_or_fail("call", identity=identity, session=session, tool=body.tool)
            if approved_now:
                # Do not create the grant until every pre-execution audit write
                # succeeds; otherwise the caller could lose the only copy.
                new_capability = session_grants.add(identity, session)
            try:
                result = driver.call(body.tool, safe_arguments)
            except DriverError as exc:
                if new_capability:
                    session_grants.revoke(identity, session)
                audit_or_fail("error", identity=identity, session=session, tool=body.tool,
                              outcome="driver_error")
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            except Exception as exc:
                if new_capability:
                    session_grants.revoke(identity, session)
                audit_or_fail("error", identity=identity, session=session, tool=body.tool,
                              outcome="driver_error")
                raise HTTPException(status_code=502, detail="cua-driver failed") from exc
            response = {"ok": True, "result": result}
            if new_capability:
                response["capability_token"] = new_capability
            return response

    @app.post("/v1/revoke")
    def revoke(
        request: Request,
        x_hermes_session: str = Header(default=""),
        x_mint_cua_capability: str = Header(default=""),
    ):
        identity = request.state.identity
        session = _normalize_session(x_hermes_session)
        with operation_lock:
            if not session_grants.allowed(identity, session, x_mint_cua_capability):
                audit_or_fail("error", identity=identity, session=session,
                              outcome="capability_denied")
                raise HTTPException(status_code=403, detail="valid capability required")
            session_grants.revoke(identity, session)
            audit_or_fail("revoke", identity=identity, session=session)
        return {"ok": True}

    app.add_middleware(SecurityMiddleware, verifier=auth, auditor=audit)
    return app


def main() -> None:
    import uvicorn
    uvicorn.run(
        create_app(), host="127.0.0.1", port=int(os.getenv("MINT_CUA_PORT", "8765")),
        proxy_headers=False, server_header=False,
    )
