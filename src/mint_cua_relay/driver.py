from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

ALLOWED_TOOLS = frozenset({
    "health_report", "list_apps", "list_windows", "get_window_state",
    "click", "double_click", "scroll", "type_text", "press_key", "set_value",
})
ACTION_TOOLS = frozenset({"click", "double_click", "scroll", "type_text", "press_key", "set_value"})
_TOKEN = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")


class DriverError(RuntimeError):
    pass


def _unknown(arguments: dict[str, Any], allowed: set[str]) -> None:
    extra = set(arguments) - allowed
    if extra:
        raise DriverError(f"unknown or unsafe argument(s): {', '.join(sorted(extra))}")


def _integer(arguments: dict[str, Any], name: str, low: int, high: int,
             *, required: bool = False) -> None:
    value = arguments.get(name)
    if value is None and not required:
        return
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise DriverError(f"{name} must be an integer from {low} to {high}")


def _boolean(arguments: dict[str, Any], name: str) -> None:
    if name in arguments and not isinstance(arguments[name], bool):
        raise DriverError(f"{name} must be boolean")


def _string(arguments: dict[str, Any], name: str, limit: int, *, required: bool = False,
            token: bool = False) -> None:
    value = arguments.get(name)
    if value is None and not required:
        return
    if not isinstance(value, str) or (required and not value) or len(value) > limit:
        raise DriverError(f"{name} must be a string of at most {limit} characters")
    if token and not _TOKEN.fullmatch(value):
        raise DriverError(f"{name} contains unsafe characters")


def _target_fields(args: dict[str, Any]) -> None:
    _integer(args, "pid", 1, 2**31 - 1)
    _integer(args, "window_id", 1, 2**63 - 1)
    _integer(args, "element_index", 0, 1_000_000)
    _string(args, "element_token", 256, token=True)
    _string(args, "snapshot_id", 9, token=True)


def _pixel_or_element(args: dict[str, Any]) -> None:
    has_token = "element_token" in args
    has_x = "x" in args
    has_y = "y" in args
    if has_x != has_y:
        raise DriverError("x and y must be provided together")
    if not has_token and not has_x:
        raise DriverError("element_token or x and y are required")
    if has_token and "pid" not in args:
        raise DriverError("element_token action requires pid")
    if has_x and ("pid" not in args or "window_id" not in args):
        raise DriverError("pixel actions require pid and window_id")
    _integer(args, "x", -100_000, 100_000)
    _integer(args, "y", -100_000, 100_000)


def _delivery(args: dict[str, Any]) -> None:
    delivery = args.pop("delivery_mode", "background")
    if delivery != "background":
        raise DriverError("delivery_mode must be background")
    args["delivery_mode"] = "background"


def validate_arguments(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if tool not in ALLOWED_TOOLS:
        raise DriverError(f"tool not allowed: {tool}")
    if not isinstance(arguments, dict):
        raise DriverError("arguments must be an object")
    args = dict(arguments)

    if tool == "health_report":
        _unknown(args, set())
    elif tool == "list_apps":
        _unknown(args, set())
    elif tool == "list_windows":
        _unknown(args, {"pid", "on_screen_only"})
        _integer(args, "pid", 1, 2**31 - 1)
        _boolean(args, "on_screen_only")
    elif tool == "get_window_state":
        _unknown(args, {
            "pid", "window_id", "query", "max_elements", "max_depth", "include_screenshot",
        })
        _integer(args, "pid", 1, 2**31 - 1, required=True)
        _integer(args, "window_id", 1, 2**63 - 1, required=True)
        _string(args, "query", 512)
        _integer(args, "max_elements", 1, 500)
        _integer(args, "max_depth", 1, 25)
        _boolean(args, "include_screenshot")
        args.setdefault("include_screenshot", False)
    elif tool in {"click", "double_click"}:
        allowed = {
            "pid", "window_id", "element_index", "element_token", "snapshot_id",
            "x", "y", "from_zoom", "delivery_mode",
        }
        if tool == "click":
            allowed.update({"button", "count", "modifier"})
        _unknown(args, allowed)
        _target_fields(args)
        if tool == "double_click" and "pid" not in args:
            raise DriverError("double_click requires pid")
        _pixel_or_element(args)
        _boolean(args, "from_zoom")
        if "button" in args and args["button"] not in {"left", "middle", "right"}:
            raise DriverError("button must be left, middle, or right")
        _integer(args, "count", 1, 3)
        modifiers = args.get("modifier", [])
        if not isinstance(modifiers, list) or len(modifiers) > 4 or any(
            item not in {"ctrl", "shift", "alt", "super"} for item in modifiers
        ):
            raise DriverError("invalid modifier")
        _delivery(args)
    elif tool == "scroll":
        _unknown(args, {"pid", "window_id", "element_index", "element_token", "snapshot_id",
                        "x", "y", "direction", "amount", "by", "delivery_mode"})
        _target_fields(args)
        _string(args, "direction", 5, required=True)
        if args["direction"] not in {"up", "down", "left", "right"}:
            raise DriverError("invalid scroll direction")
        _integer(args, "amount", 1, 50)
        if "by" in args and args["by"] not in {"line", "page"}:
            raise DriverError("by must be line or page")
        if ("x" in args) != ("y" in args):
            raise DriverError("x and y must be provided together")
        _integer(args, "x", -100_000, 100_000)
        _integer(args, "y", -100_000, 100_000)
        if "pid" not in args:
            raise DriverError("scroll requires pid")
        if "x" in args and "window_id" not in args:
            raise DriverError("pixel scroll requires window_id")
        _delivery(args)
    elif tool == "type_text":
        _unknown(args, {"pid", "window_id", "element_index", "element_token", "snapshot_id",
                        "x", "y", "text", "delivery_mode"})
        _target_fields(args)
        _string(args, "text", 4096, required=True)
        if ("x" in args) != ("y" in args):
            raise DriverError("x and y must be provided together")
        _integer(args, "x", -100_000, 100_000)
        _integer(args, "y", -100_000, 100_000)
        if "pid" not in args:
            raise DriverError("type_text requires pid")
        if "x" in args and "window_id" not in args:
            raise DriverError("pixel typing requires window_id")
        _delivery(args)
    elif tool == "press_key":
        _unknown(args, {"pid", "window_id", "element_index", "element_token", "snapshot_id",
                        "x", "y", "key", "modifiers", "delivery_mode"})
        _target_fields(args)
        _string(args, "key", 64, required=True)
        if ("x" in args) != ("y" in args):
            raise DriverError("x and y must be provided together")
        _integer(args, "x", -100_000, 100_000)
        _integer(args, "y", -100_000, 100_000)
        if "x" in args and "window_id" not in args:
            raise DriverError("pixel key input requires window_id")
        if "pid" not in args:
            raise DriverError("press_key requires pid")
        modifiers = args.get("modifiers", [])
        if not isinstance(modifiers, list) or len(modifiers) > 4 or any(
            item not in {"ctrl", "shift", "alt", "super"} for item in modifiers
        ):
            raise DriverError("invalid modifiers")
        _delivery(args)
    elif tool == "set_value":
        _unknown(args, {"pid", "window_id", "element_index", "element_token", "snapshot_id", "value"})
        _target_fields(args)
        _integer(args, "pid", 1, 2**31 - 1, required=True)
        _string(args, "element_token", 256, required=True, token=True)
        _string(args, "value", 4096, required=True)

    payload = json.dumps(args, separators=(",", ":"))
    if len(payload.encode()) > 16_384:
        raise DriverError("arguments exceed 16 KiB")
    return args


class CuaExecutor:
    def __init__(self, binary: str | None = None, socket: str | None = None,
                 timeout: int = 30) -> None:
        self.binary = binary or os.environ.get("CUA_DRIVER_BIN", "cua-driver")
        self.socket = socket or os.environ.get(
            "CUA_DRIVER_SOCKET", str(Path.home() / ".cache/cua-driver/cua-driver.sock")
        )
        self.timeout = min(max(1, timeout), 30)

    def call(self, tool: str, arguments: dict[str, Any]) -> Any:
        safe_arguments = validate_arguments(tool, arguments)
        payload = json.dumps(safe_arguments, separators=(",", ":"))
        command = [self.binary, "call", tool, payload, "--socket", self.socket]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=self.timeout,
                check=False, env=os.environ.copy(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DriverError(f"cua-driver unavailable: {exc}") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[:2000]
            raise DriverError(f"cua-driver failed ({result.returncode}): {detail}")
        text = result.stdout.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"output": text[:4096]}
