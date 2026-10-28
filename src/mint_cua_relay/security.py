from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWKClient


class AuthError(RuntimeError):
    pass


class AccessJWTVerifier:
    def __init__(self, team_domain: str, audience: str, service_token_id: str) -> None:
        domain = team_domain.strip().rstrip("/")
        if not domain.startswith("https://"):
            domain = "https://" + domain
        if not service_token_id.strip():
            raise ValueError("service token ID is required")
        self.issuer = domain
        self.audience = audience
        self.service_token_id = service_token_id.strip()
        self.jwks = PyJWKClient(f"{domain}/cdn-cgi/access/certs", cache_keys=True)

    @classmethod
    def from_env(cls) -> "AccessJWTVerifier":
        team = os.environ.get("CF_ACCESS_TEAM_DOMAIN", "")
        aud = os.environ.get("CF_ACCESS_AUD", "")
        token_id = os.environ.get("CF_ACCESS_SERVICE_TOKEN_ID", "")
        missing = [name for name, value in (
            ("CF_ACCESS_TEAM_DOMAIN", team),
            ("CF_ACCESS_AUD", aud),
            ("CF_ACCESS_SERVICE_TOKEN_ID", token_id),
        ) if not value]
        if missing:
            raise RuntimeError(f"{', '.join(missing)} are required")
        return cls(team, aud, token_id)

    def verify(self, token: str) -> dict[str, Any]:
        if not token:
            raise AuthError("missing Cf-Access-Jwt-Assertion")
        try:
            key = self.jwks.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token, key.key, algorithms=["RS256"], audience=self.audience,
                issuer=self.issuer, options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthError("invalid Cloudflare Access assertion") from exc
        if claims.get("type") != "app":
            raise AuthError("Cloudflare Access assertion is not an app token")
        if not hmac.compare_digest(str(claims.get("common_name", "")), self.service_token_id):
            raise AuthError("Cloudflare Access service token identity mismatch")
        return claims


@dataclass
class Grant:
    expires_at: float
    capability_hash: bytes


class SessionGrants:
    def __init__(self, ttl_seconds: int = 5 * 60) -> None:
        self.ttl = max(60, min(ttl_seconds, 15 * 60))
        self._grants: dict[tuple[str, str], Grant] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _hash(token: str) -> bytes:
        return hashlib.sha256(token.encode("utf-8")).digest()

    def exists(self, identity: str, session: str, now: float | None = None) -> bool:
        when = time.time() if now is None else now
        with self._lock:
            grant = self._grants.get((identity, session))
            if not grant or grant.expires_at <= when:
                self._grants.pop((identity, session), None)
                return False
            return True

    def allowed(self, identity: str, session: str, capability: str,
                now: float | None = None) -> bool:
        if not capability:
            return False
        when = time.time() if now is None else now
        candidate = self._hash(capability)
        with self._lock:
            grant = self._grants.get((identity, session))
            if not grant or grant.expires_at <= when:
                self._grants.pop((identity, session), None)
                return False
            return hmac.compare_digest(grant.capability_hash, candidate)

    def add(self, identity: str, session: str, now: float | None = None) -> str:
        when = time.time() if now is None else now
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._grants[(identity, session)] = Grant(when + self.ttl, self._hash(token))
        return token

    def revoke(self, identity: str, session: str) -> None:
        with self._lock:
            self._grants.pop((identity, session), None)
