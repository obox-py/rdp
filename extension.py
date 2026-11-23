"""远程桌面扩展：连接管理，打开时生成 .rdp 并拉起 mstsc。"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import platform
import shutil
import subprocess
from ctypes import wintypes
from pathlib import Path
from typing import Any

from obox.api.app import APP_OPEN_MSG, app_ui_message
from obox.api.component import ComponentModifyMessage
from obox.api.message import OB_BOX
from obox.api.events import CHANGE, CHECKED_CHANGE, CLICK, INPUT
from obox.api.message import COMPONENT_EVENT_MSG
from obox.api.view import view_data_message

_FIELDS_FILE = Path(__file__).with_name("fields.py")
_namespace: dict[str, Any] = {}
exec(_FIELDS_FILE.read_text(encoding="utf-8"), _namespace)
FIELDS: list[dict[str, Any]] = _namespace["FIELDS"]
FIELD_BY_NAME = {spec["field"]: spec for spec in FIELDS}

DEFAULT_PORT = 3389
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200


def normalize_connection(source: dict[str, Any]) -> dict[str, Any]:
    data = source if isinstance(source, dict) else {}
    raw_id = data.get("id")
    try:
        conn_id = int(raw_id) if raw_id not in (None, "") else None
    except (TypeError, ValueError):
        conn_id = None
    try:
        port = int(data.get("port") or DEFAULT_PORT)
    except (TypeError, ValueError):
        port = DEFAULT_PORT
    conn = {
        "id": conn_id,
        "name": str(data.get("name") or "").strip(),
        "host": str(data.get("host") or "").strip(),
        "port": port,
        "remember": bool(data.get("remember", True)),
        "password": str(data.get("password") or ""),
    }
    for spec in FIELDS:
        raw = data.get(spec["field"], spec["default"])
        if spec["kind"] == "bool":
            conn[spec["field"]] = raw if isinstance(raw, bool) else str(raw).lower() == "true"
        elif spec["kind"] == "int":
            try:
                conn[spec["field"]] = int(raw)
            except (TypeError, ValueError):
                conn[spec["field"]] = int(spec["default"])
        else:
            conn[spec["field"]] = str(raw or "")
    return conn


def validate_connection(conn: dict[str, Any], rows: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    if not conn.get("name"):
        errors.append("needName")
    else:
        same = [row for row in rows if row.get("name") == conn["name"] and row.get("id") != conn.get("id")]
        if same:
            errors.append("dupName")
    if not conn.get("host"):
        errors.append("needHost")
    port = conn.get("port")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        errors.append("badPort")
    return errors


def build_rdp_text(conn: dict[str, Any], password_blob: bytes | None = None) -> str:
    lines = [f"full address:s:{conn['host']}:{conn['port']}"]
    for spec in FIELDS:
        value = conn.get(spec["field"], spec["default"])
        text = ("1" if value else "0") if spec["kind"] == "bool" else str(value)
        lines.append(f"{spec['key']}{text}")
    if password_blob:
        lines.append(f"password 51:b:{password_blob.hex()}")
    return "\r\n".join(lines) + "\r\n"


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob(data: bytes) -> DATA_BLOB:
    buffer = ctypes.create_string_buffer(data, len(data))
    pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
    return DATA_BLOB(len(data), pointer)


def protect(data: bytes) -> bytes:
    """Windows DPAPI 加密；非 Windows 或受限环境抛 OSError。"""
    if os.name != "nt":
        raise OSError("DPAPI 仅在 Windows 可用")
    buffer = _blob(data)
    out = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(buffer), None, None, None, None, 0, ctypes.byref(out)
    )
    if not ok:
        raise OSError("CryptProtectData 失败")
    try:
        return ctypes.string_at(ctypes.cast(out.pbData, ctypes.c_void_p), out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def unprotect(data: bytes) -> bytes:
    if os.name != "nt":
        raise OSError("DPAPI 仅在 Windows 可用")
    buffer = _blob(data)
    out = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(buffer), None, None, None, None, 0, ctypes.byref(out)
    )
    if not ok:
        raise OSError("CryptUnprotectData 失败")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def find_mstsc() -> str:
    found = shutil.which("mstsc.exe") or shutil.which("mstsc")
    if found:
        return found
    for base in (os.environ.get("SystemRoot"), r"C:\\Windows"):
        if base:
            candidate = Path(base) / "System32" / "mstsc.exe"
            if candidate.is_file():
                return str(candidate)
    return ""


def launch_mstsc(mstsc: str, rdp_path: Path) -> None:
    subprocess.Popen(
        [mstsc, str(rdp_path)],
        close_fds=True,
        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
    )


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def activate(context) -> None:
    storage = Path(context.storage_dir)
    connections_path = storage / "connections.json"
    secrets_path = storage / "secrets.json"
    state: dict[str, Any] = {
        "items": [normalize_connection(row) for row in load_json(connections_path, [])],
        "query": "",
        "form": {},
        "editing": False,
        "editing_id": None,
        "status": "",
        "pending_name": "",
        "pending_delete": 0,
        "window_id": "",
    }
    secrets: dict[str, str] = dict(load_json(secrets_path, {}))

    def _filtered() -> list[dict[str, Any]]:
        text = state["query"].strip().casefold()
        if not text:
            return list(state["items"])
        return [
            item
            for item in state["items"]
            if text in item["name"].casefold() or text in item["host"].casefold()
        ]

    def _set_modal(modal_id: str, visible: bool) -> None:
        try:
            context.request(
                ComponentModifyMessage(
                    src=context.extension_id,
                    dst=OB_BOX,
                    component_id=modal_id,
                    state_type="visible",
                    value=visible,
                )
            )
        except Exception:
            pass

    def _push() -> None:
        if not state["window_id"]:
            return
        rows = [
            {
                "id": item["id"],
                "title": item["name"],
                "subtitle": f"{item['username'] + '@' if item['username'] else ''}{item['host']}:{item['port']}",
            }
            for item in _filtered()
        ]
        context.send(
            view_data_message(
                context.extension_id,
                f"app.{state['window_id']}",
                {
                    "items": rows,
                    "empty": not rows,
                    "query": state["query"],
                    "form": dict(state["form"]),
                    "editing": state["editing"],
                    "status": state["status"],
                    "pendingName": state["pending_name"],
                },
            )
        )

    def _blank_form() -> dict[str, Any]:
        form: dict[str, Any] = {
            "name": "",
            "host": "",
            "port": str(DEFAULT_PORT),
            "remember": True,
            "password": "",
        }
        for spec in FIELDS:
            form[spec["field"]] = spec["default"]
        return form

    def _open(item: dict[str, Any]) -> None:
        if platform.system() != "Windows":
            state["status"] = "windowsOnly"
            return
        mstsc = find_mstsc()
        if not mstsc:
            state["status"] = "noMstsc"
            return
        blob = None
        secret = secrets.get(str(item["id"]))
        if secret:
            try:
                blob = base64.b64decode(secret)
            except (ValueError, TypeError):
                blob = None
        text = build_rdp_text(item, blob)
        target = storage / "tmp" / f"conn-{item['id']}.rdp"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="")
        try:
            launch_mstsc(mstsc, target)
            state["status"] = "opened"
        except OSError:
            state["status"] = "noMstsc"

    def _save_form() -> None:
        conn = normalize_connection({**state["form"], "id": state.get("editing_id")})
        errors = validate_connection(conn, state["items"])
        if errors:
            state["status"] = errors[0]
            return
        if conn["id"] is None:
            conn["id"] = max([int(row["id"]) for row in state["items"]] or [0]) + 1
            state["items"].append(conn)
        else:
            state["items"] = [conn if row["id"] == conn["id"] else row for row in state["items"]]
        password = str(state["form"].get("password") or "")
        if conn["remember"]:
            if password:
                try:
                    secrets[str(conn["id"])] = base64.b64encode(protect(password.encode("utf-8"))).decode("ascii")
                except OSError:
                    secrets.pop(str(conn["id"]), None)
            elif str(conn["id"]) not in secrets:
                pass
        else:
            secrets.pop(str(conn["id"]), None)
        save_json(secrets_path, secrets)
        save_json(connections_path, state["items"])
        state["editing"] = False
        state["status"] = ""
        _set_modal("conn-modal", False)

    def _on_event(message) -> None:
        component_id = str(getattr(message, "id", "") or "")
        payload = message.payload or {}
        if message.event == INPUT and component_id == "rdp-search":
            state["query"] = str(payload.get("value") or "")
        elif component_id == "conn-name":
            state["form"]["name"] = str(payload.get("value") or "")
        elif component_id == "conn-host":
            state["form"]["host"] = str(payload.get("value") or "")
        elif component_id == "conn-port":
            state["form"]["port"] = str(payload.get("value") or "")
        elif component_id == "conn-password":
            state["form"]["password"] = str(payload.get("value") or "")
        elif component_id == "conn-remember":
            state["form"]["remember"] = bool(payload.get("checked"))
        elif component_id.startswith("f-") and message.event in (INPUT, CHANGE, CHECKED_CHANGE):
            field = component_id[2:]
            spec = FIELD_BY_NAME.get(field)
            if spec is not None:
                if spec["kind"] == "bool":
                    state["form"][field] = bool(payload.get("checked"))
                else:
                    state["form"][field] = str(payload.get("value") or "")
        elif message.event == CLICK and component_id == "rdp-new":
            state["form"] = _blank_form()
            state["editing"] = False
            state["status"] = ""
            _push()
            _set_modal("conn-modal", True)
            return
        elif message.event == CLICK and component_id == "conn-save":
            _save_form()
        elif message.event == CLICK and component_id == "conn-cancel":
            state["editing"] = False
            state["status"] = ""
            _set_modal("conn-modal", False)
        elif message.event == CLICK and component_id.startswith("open-"):
            item = next((row for row in state["items"] if f"open-{row['id']}" == component_id), None)
            if item is not None:
                _open(item)
        elif message.event == CLICK and component_id.startswith("edit-"):
            item = next((row for row in state["items"] if f"edit-{row['id']}" == component_id), None)
            if item is not None:
                state["form"] = {**item, "port": str(item["port"]), "password": ""}
                state["editing"] = True
                state["editing_id"] = item["id"]
                state["status"] = ""
                _push()
                _set_modal("conn-modal", True)
                return
        elif message.event == CLICK and component_id == "delete-cancel":
            state["pending_delete"] = 0
            state["pending_name"] = ""
            _set_modal("confirm-modal", False)
        elif message.event == CLICK and component_id == "delete-ok":
            target = state["pending_delete"]
            state["items"] = [row for row in state["items"] if row["id"] != target]
            secrets.pop(str(target), None)
            save_json(secrets_path, secrets)
            save_json(connections_path, state["items"])
            state["pending_delete"] = 0
            state["pending_name"] = ""
            state["status"] = ""
            _set_modal("confirm-modal", False)
        elif message.event == "close" and component_id == "confirm-modal":
            state["pending_delete"] = 0
            state["pending_name"] = ""
        elif message.event == "close" and component_id == "conn-modal":
            state["editing"] = False
            state["status"] = ""
        elif message.event == CLICK and component_id.startswith("del-"):
            item = next((row for row in state["items"] if f"del-{row['id']}" == component_id), None)
            if item is not None:
                state["pending_delete"] = item["id"]
                state["pending_name"] = item["name"]
                state["status"] = ""
                _push()
                _set_modal("confirm-modal", True)
                return
        _push()

    def _on_open(message) -> None:
        payload = message.payload or {}
        state["window_id"] = str(payload.get("window_id") or "")
        context.send(app_ui_message(context.extension_id, state["window_id"], oml="views/main.oml"))
        _push()

    context.on(APP_OPEN_MSG, _on_open)
    context.on(COMPONENT_EVENT_MSG, _on_event)


def deactivate(context) -> None:
    context.subscriptions.clear()