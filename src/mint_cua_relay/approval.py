from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass

_SAFE = re.compile(r"[^A-Za-z0-9 ._:@/-]")
PROMPT_TIMEOUT_SECONDS = 45


@dataclass(frozen=True)
class ApprovalRequest:
    identity: str
    session: str
    action: str


def _clean(value: str, limit: int = 120) -> str:
    return _SAFE.sub("?", value)[:limit]


def _zenity(req: ApprovalRequest) -> bool:
    zenity = shutil.which("zenity")
    if not zenity:
        return False
    text = (
        "Allow remote desktop control for this session?\n\n"
        f"Identity: {_clean(req.identity)}\n"
        f"Session: {_clean(req.session)}\n"
        f"First action: {_clean(req.action)}\n\n"
        "Approval is time-limited and can be revoked."
    )
    try:
        result = subprocess.run(
            [zenity, "--question", "--title=Mint CUA Relay", f"--text={text}",
             "--ok-label=Allow session", "--cancel-label=Deny",
             f"--timeout={PROMPT_TIMEOUT_SECONDS}"],
            env=os.environ.copy(), timeout=PROMPT_TIMEOUT_SECONDS, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _gtk(req: ApprovalRequest) -> bool | None:
    try:
        import gi  # type: ignore
        gi.require_version("Gtk", "3.0")
        from gi.repository import GLib, Gtk  # type: ignore
    except (ImportError, ValueError):
        return None
    text = (
        f"Identity: {_clean(req.identity)}\nSession: {_clean(req.session)}\n"
        f"First action: {_clean(req.action)}\n\n"
        "Allow remote desktop control for this session?"
    )
    dialog = Gtk.MessageDialog(
        transient_for=None, flags=0, message_type=Gtk.MessageType.WARNING,
        buttons=Gtk.ButtonsType.NONE, text="Mint CUA Relay approval",
    )
    dialog.format_secondary_text(text)
    dialog.add_button("Deny", Gtk.ResponseType.CANCEL)
    dialog.add_button("Allow session", Gtk.ResponseType.OK)
    timer = GLib.timeout_add_seconds(
        PROMPT_TIMEOUT_SECONDS, lambda: dialog.response(Gtk.ResponseType.CANCEL) or False
    )
    try:
        return dialog.run() == Gtk.ResponseType.OK
    finally:
        GLib.source_remove(timer)
        dialog.destroy()


def prompt(req: ApprovalRequest) -> bool:
    """Prompt locally for at most 45 seconds; every GUI failure denies."""
    try:
        gtk_result = _gtk(req)
        if gtk_result is not None:
            return bool(gtk_result)
        return _zenity(req)
    except Exception:
        return False
