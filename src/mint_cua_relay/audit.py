from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any


class AuditLog:
    """Append-only metadata audit. Values are deliberately restricted."""

    EVENTS = frozenset({"approve", "deny", "call", "revoke", "error"})

    def __init__(self, path: str | Path | None = None) -> None:
        default = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
        self.path = Path(path or os.environ.get(
            "MINT_CUA_AUDIT_LOG", default / "mint-cua-relay/audit.jsonl"
        ))
        self._lock = threading.Lock()

    def write(self, event: str, *, identity: str = "", session: str = "", tool: str = "",
              outcome: str = "") -> None:
        if event not in self.EVENTS:
            raise ValueError("invalid audit event")
        record: dict[str, Any] = {
            "timestamp": int(time.time()),
            "event": event,
        }
        if identity:
            record["identity"] = identity[:160]
        if session:
            record["session"] = session[:160]
        if tool:
            record["tool"] = tool[:80]
        if outcome:
            record["outcome"] = outcome[:80]
        encoded = (json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n").encode()
        with self._lock:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self.path.parent, 0o700)
            fd = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                os.fchmod(fd, 0o600)
                written = os.write(fd, encoded)
                if written != len(encoded):
                    raise OSError("short audit write")
                os.fsync(fd)
            finally:
                os.close(fd)
