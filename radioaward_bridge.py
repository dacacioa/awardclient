#!/usr/bin/env python3
"""
README
------
1) Requiere Python 3.12+ y la libreria requests: `pip install requests`.
2) Ejecute `python radioaward_bridge.py` (opcionalmente cree un venv antes).
3) HamActivity Bridge almacena la URL base, API key y puerto UDP en un JSON dentro de la
   carpeta del usuario, por lo que no necesita variables de entorno adicionales.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import struct
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
import xml.etree.ElementTree as ET

import requests
import tkinter as tk
from tkinter import messagebox, ttk


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(threadName)s - %(message)s",
)
LOGGER = logging.getLogger(__name__)


def utc_now() -> dt.datetime:
    """Return timezone-aware UTC timestamps to avoid datetime warnings."""
    return dt.datetime.now(dt.timezone.utc)


# -- default settings (persisted per user) -------------------------------------
DEFAULT_SETTINGS = {
    "base_url": "https://activacionsbackend.urcat.cat/",
    "api_key": "",
    "udp_port": 9091,
    "log_profile": "N1MM",
    "debug": False,
    "last_diploma_id": "",
}


class SettingsManager:
    """Persist GUI preferences in a JSON file under the user profile."""

    def __init__(self, filename: Optional[Path] = None) -> None:
        config_name = filename or (Path.home() / ".hamactivity_bridge_settings.json")
        self.path = config_name
        self.legacy_path = Path.home() / ".radioaward_bridge_settings.json"

    def load(self) -> Dict[str, Any]:
        source_path = self.path if self.path.exists() else self.legacy_path
        if source_path.exists():
            try:
                data = json.loads(source_path.read_text(encoding="utf-8"))
                if data.get("base_url") == "https://RADIOAWARD_HOST":
                    data["base_url"] = DEFAULT_SETTINGS["base_url"]
                LOGGER.debug("Loaded settings from %s", source_path)
                return {**DEFAULT_SETTINGS, **data}
            except Exception as exc:  # pragma: no cover - defensive
                LOGGER.error("Failed to load settings: %s", exc)
        return DEFAULT_SETTINGS.copy()

    def save(self, settings: Dict[str, Any]) -> None:
        try:
            self.path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
            LOGGER.info("Settings saved to %s", self.path)
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.error("Unable to save settings: %s", exc)
            raise


class ApiClient:
    """Thin wrapper around the HamActivity REST API."""

    def __init__(self, base_url: str, api_key: str = "") -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._session = requests.Session()

    @property
    def api_key(self) -> str:
        return self._api_key

    def set_base_url(self, base_url: str) -> None:
        self._base_url = base_url.rstrip("/")
        LOGGER.debug("Base URL updated to %s", self._base_url)

    def set_api_key(self, api_key: str) -> None:
        self._api_key = api_key.strip()
        LOGGER.debug("API key updated (hidden)")

    def login(self, api_key: Optional[str] = None) -> Dict[str, Any]:
        key = (api_key or self._api_key or "").strip()
        if not key:
            raise ValueError("La API key es obligatoria.")
        if len(key) < 8:
            raise ValueError("La API key debe tener al menos 8 caracteres.")

        payload = {"apiKey": key}
        url = f"{self._base_url}/api/public/operators/login"
        LOGGER.info("Validating API key at %s", url)
        response = self._session.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )

        if response.status_code == 200:
            self._api_key = key
            LOGGER.info("API key valid. Operator data received.")
            return response.json()

        raise requests.HTTPError(
            f"Login failed with status {response.status_code}: {response.text}",
            response=response,
        )

    def send_contact(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self._base_url}/api/public/contacts"
        headers = {"Content-Type": "application/json"}
        last_exc: Optional[Exception] = None

        for attempt in range(1, 4):
            try:
                LOGGER.info("Sending contact attempt %s", attempt)
                response = self._session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=10,
                )
                if response.status_code == 201:
                    LOGGER.info("Contact stored successfully.")
                    return response.json()
                msg = (
                    f"Contact failed ({response.status_code}): "
                    f"{response.text.strip()}"
                )
                LOGGER.warning(msg)
                raise requests.HTTPError(msg, response=response)
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_exc = exc
                LOGGER.warning("Network error: %s", exc)
                if attempt < 3:
                    time.sleep(2 ** (attempt - 1))  # backoff 1s, 2s
            except requests.HTTPError as exc:
                raise

        raise last_exc or RuntimeError("Failed to send contact after retries.")


class UdpListener:
    """Receive UDP datagrams from N1MM without blocking the GUI."""

    def __init__(
        self,
        port: int,
        callback: Callable[[Dict[str, str]], None],
        error_callback: Optional[Callable[[str], None]] = None,
        log_callback: Optional[Callable[[str], None]] = None,
        parse_func: Optional[Callable[[Union[bytes, str]], Dict[str, str]]] = None,
    ) -> None:
        self.port = port
        self.callback = callback
        self.error_callback = error_callback
        self.log_callback = log_callback
        self.parse_func = parse_func
        self._socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()

    def start(self) -> None:
        if self._running.is_set():
            return
        self._running.set()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        LOGGER.info("UDP listener started on port %s", self.port)

    def stop(self) -> None:
        self._running.clear()
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
        LOGGER.info("UDP listener stopped.")

    def is_running(self) -> bool:
        return self._running.is_set()

    def _run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            sock.bind(("", self.port))
        except OSError as exc:
            LOGGER.error("Cannot bind UDP port %s: %s", self.port, exc)
            if self.error_callback:
                self.error_callback(f"No se pudo abrir el puerto {self.port}: {exc}")
            self._running.clear()
            return

        self._socket = sock

        while self._running.is_set():
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            text_payload = data.decode("utf-8", errors="ignore").strip()
            if not data:
                continue

            LOGGER.debug("Datagram received: %s", text_payload or data.hex())
            if self.log_callback:
                self.log_callback(f"UDP recibido: {text_payload or data.hex()}")
            parser = self.parse_func or self._parse_datagram
            parsed = parser(data)
            if parsed and parsed.get("CALL", "").strip():
                self.callback(parsed)

        try:
            sock.close()
        except OSError:
            pass

    @staticmethod
    def _parse_datagram(text: Union[bytes, str]) -> Dict[str, str]:
        if isinstance(text, bytes):
            text = text.decode("utf-8", errors="ignore")
        stripped = text.strip()
        if not stripped:
            return {}

        if stripped.startswith("<"):
            try:
                root = ET.fromstring(stripped)
            except ET.ParseError as exc:
                LOGGER.error("Invalid XML datagram: %s", exc)
                return {}
            fields = {}
            for child in root:
                fields[child.tag.strip().upper()] = (child.text or "").strip()
            return fields

        fields: Dict[str, str] = {}
        for chunk in stripped.split("\t"):
            if "=" not in chunk:
                continue
            key, value = chunk.split("=", 1)
            fields[key.strip().upper()] = value.strip()
        return fields


class WsjtxDatagramReader:
    """Minimal QDataStream reader for WSJT-X/JTDX UDP QSO Logged packets."""

    MAGIC = 0xADBCCBDA

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def read_u8(self) -> int:
        return self._unpack(">B")

    def read_u32(self) -> int:
        return self._unpack(">I")

    def read_u64(self) -> int:
        return self._unpack(">Q")

    def read_i32(self) -> int:
        return self._unpack(">i")

    def read_i64(self) -> int:
        return self._unpack(">q")

    def read_utf8(self) -> str:
        length = self.read_u32()
        if length == 0xFFFFFFFF:
            return ""
        raw = self._read(length)
        return raw.decode("utf-8", errors="replace").strip()

    def read_qdatetime(self) -> Optional[dt.datetime]:
        julian_day = self.read_i64()
        msecs_since_midnight = self.read_u32()
        time_spec = self.read_u8()
        utc_offset_seconds = 0
        if time_spec == 2:
            utc_offset_seconds = self.read_i32()

        if julian_day <= 0 or msecs_since_midnight >= 86_400_000:
            return None

        date_value = self._date_from_julian_day(julian_day)
        time_value = (
            dt.datetime.min
            + dt.timedelta(milliseconds=msecs_since_midnight)
        ).time()
        value = dt.datetime.combine(date_value, time_value, tzinfo=dt.timezone.utc)
        if time_spec == 2:
            value -= dt.timedelta(seconds=utc_offset_seconds)
        return value.astimezone(dt.timezone.utc)

    def _read(self, length: int) -> bytes:
        end = self.offset + length
        if end > len(self.data):
            raise IndexError("datagram ended before field was complete")
        chunk = self.data[self.offset:end]
        self.offset = end
        return chunk

    def _unpack(self, fmt: str) -> int:
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, self._read(size))[0]

    @staticmethod
    def _date_from_julian_day(julian_day: int) -> dt.date:
        # Fliegel-Van Flandern conversion from Julian day number to Gregorian date.
        l_value = julian_day + 68569
        n_value = 4 * l_value // 146097
        l_value = l_value - (146097 * n_value + 3) // 4
        i_value = 4000 * (l_value + 1) // 1461001
        l_value = l_value - 1461 * i_value // 4 + 31
        j_value = 80 * l_value // 2447
        day = l_value - 2447 * j_value // 80
        l_value = j_value // 11
        month = j_value + 2 - 12 * l_value
        year = 100 * (n_value - 49) + i_value + l_value
        return dt.date(year, month, day)


@dataclass
class Diploma:
    id: str
    title: str
    start_date: Optional[str]
    end_date: Optional[str]

    def label(self) -> str:
        start = self.start_date or "-"
        end = self.end_date or "abierto"
        return f"{self.title} ({start} -> {end})"


class MainWindow:
    """Tk main window wiring GUI, API client and UDP listener together."""

    DEDUPE_WINDOW_SECONDS = 60
    FUTURE_QSO_TOLERANCE_SECONDS = 5

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("HamActivity Bridge")

        self.settings_manager = SettingsManager()
        settings = self.settings_manager.load()
        self.api_client = ApiClient(settings["base_url"], settings["api_key"])
        self.udp_listener: Optional[UdpListener] = None
        self.diplomas: List[Diploma] = []
        self.selected_diploma_id: Optional[str] = None
        self.last_diploma_id = str(settings.get("last_diploma_id") or "").strip()
        self.qso_counter = 0
        self.is_logged_in = False
        self.log_profile = tk.StringVar(value=settings.get("log_profile", "N1MM"))
        self.debug_var = tk.BooleanVar(value=settings.get("debug", False))
        self._dedupe_lock = threading.Lock()
        self._sent_signatures: dict[tuple, set[dt.datetime]] = {}
        self._attempt_signatures: dict[tuple, set[dt.datetime]] = {}

        self._build_ui(settings)
        self._update_login_state(False, "Desconectado")
        self._log("Aplicacion iniciada.")

    def _build_ui(self, settings: Dict[str, Any]) -> None:
        padding = {"padx": 8, "pady": 4}

        # Settings frame
        settings_frame = ttk.LabelFrame(self.root, text="Ajustes")
        settings_frame.grid(row=0, column=0, sticky="ew", **padding)
        settings_frame.columnconfigure(1, weight=1)

        ttk.Label(settings_frame, text="URL base:").grid(row=0, column=0, sticky="w")
        self.base_url_var = tk.StringVar(value=settings["base_url"])
        self.base_url_entry = ttk.Entry(settings_frame, textvariable=self.base_url_var)
        self.base_url_entry.grid(row=0, column=1, sticky="ew")

        ttk.Label(settings_frame, text="API key:").grid(row=1, column=0, sticky="w")
        self.api_key_var = tk.StringVar(value=settings["api_key"])
        self.api_entry = ttk.Entry(
            settings_frame, textvariable=self.api_key_var, show="*"
        )
        self.api_entry.grid(row=1, column=1, sticky="ew")
        ttk.Button(settings_frame, text="Guardar", command=self.save_settings).grid(
            row=1, column=2, padx=4
        )

        ttk.Label(settings_frame, text="Puerto UDP:").grid(row=2, column=0, sticky="w")
        self.udp_port_var = tk.IntVar(value=settings["udp_port"])
        self.udp_port_entry = ttk.Entry(
            settings_frame, textvariable=self.udp_port_var, width=10
        )
        self.udp_port_entry.grid(row=2, column=1, sticky="w")
        ttk.Checkbutton(
            settings_frame, text="Debug", variable=self.debug_var
        ).grid(row=2, column=2, padx=4, sticky="w")


        # Login frame
        login_frame = ttk.LabelFrame(self.root, text="Operador")
        login_frame.grid(row=1, column=0, sticky="ew", **padding)
        login_frame.columnconfigure(2, weight=1)
        login_frame.columnconfigure(3, weight=1)

        self.login_status_label = tk.Label(
            login_frame, text="Estado: Desconocido", bg="orange", fg="white"
        )
        self.login_status_label.grid(row=0, column=0, columnspan=4, sticky="ew", pady=2)

        self.login_button = ttk.Button(
            login_frame, text="Login", command=self.handle_login_logout, width=12
        )
        self.login_button.grid(
            row=1, column=0, rowspan=2, padx=(4, 8), pady=(2, 0), ipadx=8, ipady=6, sticky="nsw"
        )

        ttk.Label(login_frame, text="Log:").grid(row=1, column=1, sticky="e")
        self.log_profile_combo = ttk.Combobox(
            login_frame,
            values=["N1MM", "WSJT-X/JTDX"],
            state="readonly",
            textvariable=self.log_profile,
            width=16,
        )
        self.log_profile_combo.grid(row=1, column=2, sticky="w")
        self.log_profile_combo.set(self.log_profile.get())
        self.log_profile_combo.bind("<<ComboboxSelected>>", self._on_log_profile_changed)

        ttk.Label(login_frame, text="Diploma:").grid(row=2, column=1, sticky="e", pady=(4, 0))
        self.diplomas_var = tk.StringVar()
        self.diploma_combo = ttk.Combobox(
            login_frame, textvariable=self.diplomas_var, state="readonly"
        )
        self.diploma_combo.grid(row=2, column=2, columnspan=2, sticky="ew", pady=(4, 0))
        self.diploma_combo.bind("<<ComboboxSelected>>", self._on_diploma_selected)

        # Status frame
        status_frame = ttk.LabelFrame(self.root, text="Estado de envio")
        status_frame.grid(row=2, column=0, sticky="ew", **padding)
        status_frame.columnconfigure(1, weight=1)

        ttk.Label(status_frame, text="Ultimo OK:").grid(row=0, column=0, sticky="w")
        self.last_success_var = tk.StringVar(value="N/A")
        ttk.Label(status_frame, textvariable=self.last_success_var).grid(
            row=0, column=1, sticky="w"
        )

        ttk.Label(status_frame, text="Ultimo error:").grid(row=1, column=0, sticky="w")
        self.last_error_var = tk.StringVar(value="N/A")
        ttk.Label(status_frame, textvariable=self.last_error_var).grid(
            row=1, column=1, sticky="w"
        )

        ttk.Label(status_frame, text="QSOs enviados:").grid(row=2, column=0, sticky="w")
        self.qso_count_var = tk.StringVar(value="0")
        ttk.Label(status_frame, textvariable=self.qso_count_var).grid(
            row=2, column=1, sticky="w"
        )

        # Log frame
        log_frame = ttk.LabelFrame(self.root, text="Registro")
        log_frame.grid(row=3, column=0, sticky="nsew", **padding)
        self.root.rowconfigure(3, weight=1)
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log_text = tk.Text(log_frame, height=12, state="disabled")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text["yscrollcommand"] = scrollbar.set
        self._enable_context_menus()

    def _enable_context_menus(self) -> None:
        editable_widgets = (
            self.base_url_entry,
            self.api_entry,
            self.udp_port_entry,
        )
        for widget in editable_widgets:
            self._bind_context_menu(widget, readonly=False)
        self._bind_context_menu(self.log_text, readonly=True)

    def _bind_context_menu(self, widget: tk.Widget, readonly: bool) -> None:
        widget.bind(
            "<Button-3>",
            lambda event, target=widget, read_only=readonly: self._show_context_menu(
                event, target, read_only
            ),
        )
        widget.bind(
            "<Control-a>",
            lambda event, target=widget: self._select_all(target),
        )

    def _show_context_menu(
        self, event: tk.Event, widget: tk.Widget, readonly: bool
    ) -> str:
        widget.focus_set()
        menu = tk.Menu(self.root, tearoff=False)
        if not readonly:
            menu.add_command(
                label="Cortar",
                command=lambda: widget.event_generate("<<Cut>>"),
            )
        menu.add_command(
            label="Copiar",
            command=lambda: widget.event_generate("<<Copy>>"),
        )
        if not readonly:
            menu.add_command(
                label="Pegar",
                command=lambda: widget.event_generate("<<Paste>>"),
            )
        menu.add_separator()
        menu.add_command(label="Seleccionar todo", command=lambda: self._select_all(widget))
        menu.tk_popup(event.x_root, event.y_root)
        return "break"

    @staticmethod
    def _select_all(widget: tk.Widget) -> str:
        if isinstance(widget, tk.Text):
            widget.tag_add("sel", "1.0", "end-1c")
        else:
            widget.selection_range(0, "end")  # type: ignore[attr-defined]
            widget.icursor("end")  # type: ignore[attr-defined]
        return "break"

    def _collect_settings(self) -> Dict[str, Any]:
        return {
            "base_url": self.base_url_var.get().strip(),
            "api_key": self.api_key_var.get().strip(),
            "udp_port": self.udp_port_var.get(),
            "log_profile": self.log_profile.get(),
            "debug": bool(self.debug_var.get()),
            "last_diploma_id": (self.selected_diploma_id or self.last_diploma_id or "").strip(),
        }

    def _save_settings(self, show_message: bool) -> None:
        old_port = self.udp_listener.port if self.udp_listener else None
        settings = self._collect_settings()
        self.settings_manager.save(settings)
        self.api_client.set_base_url(settings["base_url"])
        self.api_client.set_api_key(settings["api_key"])
        self.log_profile.set(settings["log_profile"])
        self.last_diploma_id = settings["last_diploma_id"]
        if settings["udp_port"] != old_port:
            self._restart_udp_listener(settings["udp_port"])
        if show_message:
            messagebox.showinfo("Ajustes", "Ajustes guardados correctamente.")

    def save_settings(self) -> None:
        try:
            self._save_settings(show_message=True)
        except Exception as exc:
            messagebox.showerror("Ajustes", f"No se pudieron guardar: {exc}")

    def handle_login_logout(self) -> None:
        if self.is_logged_in:
            self._perform_logout()
            return

        api_key = self.api_key_var.get().strip()
        base_url = self.base_url_var.get().strip()

        if not api_key:
            messagebox.showwarning("Login", "Introduce una API key.")
            return
        if len(api_key) < 8:
            messagebox.showwarning("Login", "La API key debe tener al menos 8 caracteres.")
            return

        self.api_client.set_base_url(base_url)
        self.api_client.set_api_key(api_key)
        threading.Thread(target=self._login_worker, daemon=True).start()

    def _login_worker(self) -> None:
        self._set_login_button_state(False)
        try:
            data = self.api_client.login()
            operator = data["operator"]
            diplomas = [
                Diploma(
                    id=item["id"],
                    title=item["title"],
                    start_date=item.get("startDate"),
                    end_date=item.get("endDate"),
                )
                for item in data.get("diplomas", [])
            ]
            self.root.after(
                0,
                lambda operator=operator, diplomas=diplomas: self._on_login_success(
                    operator, diplomas
                ),
            )
        except Exception as exc:
            LOGGER.exception("Login failed: %s", exc)
            self.root.after(0, lambda err=exc: self._on_login_error(err))

    def _set_login_button_state(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.root.after(0, lambda: self.login_button.config(state=state))

    def _on_login_success(self, operator: Dict[str, Any], diplomas: List[Diploma]) -> None:
        self._set_login_button_state(True)
        self.diplomas = diplomas
        if diplomas:
            self.diploma_combo["values"] = [d.label() for d in diplomas]
            remembered_idx = next(
                (idx for idx, diploma in enumerate(diplomas) if diploma.id == self.last_diploma_id),
                -1,
            )
            selected_idx = remembered_idx if remembered_idx >= 0 else 0
            self.diploma_combo.current(selected_idx)
            self.selected_diploma_id = diplomas[selected_idx].id
            self.last_diploma_id = self.selected_diploma_id
        else:
            self.diploma_combo.set("")
            self.selected_diploma_id = None
            self.last_diploma_id = ""
        operator_callsign = (
            operator.get("callsign") or operator.get("displayName") or operator.get("username")
        )
        self._update_login_state(True, f"Conectado como {operator_callsign}")
        self._log(f"Login OK: {operator.get('callsign')} ({operator.get('username')})")
        self.login_button.config(text="Logout")
        try:
            self._save_settings(show_message=False)
        except Exception as exc:
            LOGGER.warning("Unable to persist active diploma after login: %s", exc)
        self._ensure_udp_listener_running()

    def _on_login_error(self, exc: Exception) -> None:
        self._set_login_button_state(True)
        self._update_login_state(False, "Error de login")
        messagebox.showerror("Login", str(exc))
        self._log(f"Login error: {exc}")
        self.login_button.config(text="Login")

    def _update_login_state(self, ok: bool, text: str) -> None:
        color = "green" if ok else "red"
        self.login_status_label.config(text=text, bg=color)
        self.is_logged_in = ok

    def _on_diploma_selected(self, _event: Any) -> None:
        idx = self.diploma_combo.current()
        if idx >= 0 and idx < len(self.diplomas):
            self.selected_diploma_id = self.diplomas[idx].id
            self.last_diploma_id = self.selected_diploma_id
            try:
                self._save_settings(show_message=False)
            except Exception as exc:
                LOGGER.warning("Unable to persist selected diploma: %s", exc)

    def _on_log_profile_changed(self, _event: Any) -> None:
        if self.log_profile.get().strip().lower() in {"wsjt-x/jtdx", "wsjtx", "jtdx"}:
            if self.udp_port_var.get() == DEFAULT_SETTINGS["udp_port"]:
                self.udp_port_var.set(2237)
        if self.is_logged_in:
            self._restart_udp_listener(self.udp_port_var.get())

    def _restart_udp_listener(self, port: int) -> None:
        if self.udp_listener and self.udp_listener.is_running():
            self.udp_listener.stop()
            self.udp_listener = None
        if self.is_logged_in:
            self._start_udp_listener(port)

    def _start_udp_listener(self, port: int) -> None:
        self.udp_listener = UdpListener(
            port,
            self._handle_incoming_qso,
            error_callback=self._handle_udp_error,
            log_callback=lambda msg: self._log(msg, debug_only=True),
            parse_func=self._get_parser_for_profile(),
        )
        self.udp_listener.start()

    def _ensure_udp_listener_running(self) -> None:
        if self.is_logged_in and not (self.udp_listener and self.udp_listener.is_running()):
            self._start_udp_listener(self.udp_port_var.get())

    def _handle_udp_error(self, message: str) -> None:
        def _notify() -> None:
            messagebox.showerror("UDP", message)
            self.udp_listener = None

        self.root.after(0, _notify)

    def _handle_incoming_qso(self, qso_fields: Dict[str, str]) -> None:
        threading.Thread(
            target=self._send_qso_worker, args=(qso_fields,), daemon=True
        ).start()

    def _send_qso_worker(self, qso_fields: Dict[str, str]) -> None:
        payload = self._build_contact_payload(qso_fields)
        if not payload:
            LOGGER.warning("Incomplete QSO data: %s", qso_fields)
            return

        timestamp = utc_now().strftime("%H:%M:%S")
        qso_datetime = self._parse_qso_datetime(payload.get("qsoDateTime"))
        if self._is_future_qso_datetime(qso_datetime):
            message = (
                f"QSO rechazado por fecha/hora futura: {self._format_qso_summary(payload)}"
            )
            self.root.after(
                0,
                lambda: self.last_error_var.set(
                    f"{utc_now().strftime('%Y-%m-%dT%H:%M:%SZ')} - {message}"
                ),
            )
            self._log(f"[{timestamp}] {message}")
            LOGGER.warning("Rejected future QSO: %s", payload)
            return

        signature, qso_datetime = self._build_dedupe_signature(payload)
        with self._dedupe_lock:
            self._prune_signature_times(signature, qso_datetime)
            if self._is_duplicate_signature(signature, qso_datetime):
                self._log(
                    f"[{timestamp}] QSO duplicado ignorado: {self._format_qso_summary(payload)}"
                )
                return
            self._store_signature_time(self._attempt_signatures, signature, qso_datetime)

        if self.debug_var.get():
            self._log(f"[{timestamp}] Request: {json.dumps(payload)}")
        else:
            self._log(self._format_qso_summary(payload))

        try:
            response = self.api_client.send_contact(payload)
            self.qso_counter += 1
            self.root.after(
                0,
                lambda: self.last_success_var.set(
                    utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
                ),
            )
            self.root.after(0, lambda: self.qso_count_var.set(str(self.qso_counter)))
            if self.debug_var.get():
                self._log(f"[{timestamp}] Response: {response}")
            with self._dedupe_lock:
                self._store_signature_time(self._sent_signatures, signature, qso_datetime)
                self._discard_signature_time(
                    self._attempt_signatures, signature, qso_datetime
                )
        except Exception as exc:
            LOGGER.exception("Error sending contact: %s", exc)
            self.root.after(
                0,
                lambda: self.last_error_var.set(
                    f"{utc_now().strftime('%Y-%m-%dT%H:%M:%SZ')} - {exc}"
                ),
            )
            self._log(f"[{timestamp}] Error: {exc}")
            with self._dedupe_lock:
                self._discard_signature_time(
                    self._attempt_signatures, signature, qso_datetime
                )

    def _build_contact_payload(self, data: Dict[str, str]) -> Optional[Dict[str, Any]]:
        api_key = (self.api_client.api_key or "").strip()
        diploma_id = (self.selected_diploma_id or "").strip()
        if not api_key or len(api_key) < 8 or not diploma_id:
            return None

        call = data.get("CALL", "").strip().upper()
        if not call or len(call) < 2:
            return None

        qso_dt = self._extract_qso_datetime(data)

        payload: Dict[str, Any] = {
            "apiKey": api_key,
            "diplomaId": diploma_id,
            "callsign": call,
        }
        if qso_dt:
            payload["qsoDateTime"] = qso_dt

        band_value = self._normalize_band(
            data.get("BAND"),
            data.get("FREQ") or data.get("RXFREQ") or data.get("TXFREQ"),
        )
        if band_value:
            payload["band"] = band_value

        if mode := self._normalize_mode(data.get("MODE")):
            payload["mode"] = mode

        freq_value = self._normalize_frequency(
            data.get("FREQ") or data.get("RXFREQ") or data.get("TXFREQ"),
            band_hint=band_value,
        )
        if freq_value:
            payload["frequency"] = freq_value

        rst_sent = self._normalize_exchange(
            self._resolve_exchange(
                data,
                primary_keys=("STX_STRING", "SENTEXCHANGE", "SENT_EXCHANGE", "RST_SENT"),
                report_key="SNT",
                serial_key="SNTNR",
            )
        )
        rst_rcvd = self._normalize_exchange(
            self._resolve_exchange(
                data,
                primary_keys=(
                    "SRX_STRING",
                    "RECEIVEDEXCHANGE",
                    "RECEIVED_EXCHANGE",
                    "RST_RCVD",
                ),
                report_key="RCV",
                serial_key="RCVNR",
            )
        )
        if rst_sent:
            payload["rstSent"] = rst_sent
        if rst_rcvd:
            payload["rstRcvd"] = rst_rcvd

        country_value = data.get("COUNTRY") or data.get("COUNTRYPREFIX")
        if country_value:
            country_clean = str(country_value).strip()
            if country_clean:
                payload["country"] = country_clean[:120]

        dxcc_value = data.get("DXCC")
        if dxcc_value is not None:
            dxcc_clean = str(dxcc_value).strip()
            if dxcc_clean:
                payload["dxcc"] = dxcc_clean[:16]

        return payload

    def _build_dedupe_signature(
        self, payload: Dict[str, Any]
    ) -> tuple[tuple[str, str, str, str], Optional[dt.datetime]]:
        qso_datetime = self._parse_qso_datetime(payload.get("qsoDateTime"))
        return (
            str(payload.get("diplomaId") or "").strip(),
            str(payload.get("callsign") or "").strip().upper(),
            str(payload.get("band") or "").strip().upper(),
            str(payload.get("mode") or "").strip().upper(),
        ), qso_datetime

    @staticmethod
    def _parse_qso_datetime(value: Any) -> Optional[dt.datetime]:
        if not value:
            return None
        clean = str(value).strip()
        if not clean:
            return None
        if clean.endswith("Z"):
            clean = clean[:-1] + "+00:00"
        try:
            parsed = dt.datetime.fromisoformat(clean)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        else:
            parsed = parsed.astimezone(dt.timezone.utc)
        return parsed

    def _is_future_qso_datetime(self, qso_datetime: Optional[dt.datetime]) -> bool:
        if qso_datetime is None:
            return False
        return qso_datetime > utc_now() + dt.timedelta(
            seconds=self.FUTURE_QSO_TOLERANCE_SECONDS
        )

    def _is_duplicate_signature(
        self, signature: tuple[str, str, str, str], qso_datetime: Optional[dt.datetime]
    ) -> bool:
        if qso_datetime is None:
            return False
        for seen_at in self._sent_signatures.get(signature, set()):
            if abs((qso_datetime - seen_at).total_seconds()) <= self.DEDUPE_WINDOW_SECONDS:
                return True
        for seen_at in self._attempt_signatures.get(signature, set()):
            if abs((qso_datetime - seen_at).total_seconds()) <= self.DEDUPE_WINDOW_SECONDS:
                return True
        return False

    @staticmethod
    def _store_signature_time(
        store: dict[tuple[str, str, str, str], set[dt.datetime]],
        signature: tuple[str, str, str, str],
        qso_datetime: Optional[dt.datetime],
    ) -> None:
        if qso_datetime is None:
            return
        store.setdefault(signature, set()).add(qso_datetime)

    @staticmethod
    def _discard_signature_time(
        store: dict[tuple[str, str, str, str], set[dt.datetime]],
        signature: tuple[str, str, str, str],
        qso_datetime: Optional[dt.datetime],
    ) -> None:
        if qso_datetime is None:
            return
        values = store.get(signature)
        if not values:
            return
        values.discard(qso_datetime)
        if not values:
            store.pop(signature, None)

    def _prune_signature_times(
        self, signature: tuple[str, str, str, str], qso_datetime: Optional[dt.datetime]
    ) -> None:
        if qso_datetime is None:
            return
        cutoff = qso_datetime - dt.timedelta(seconds=self.DEDUPE_WINDOW_SECONDS)
        for store in (self._sent_signatures, self._attempt_signatures):
            values = store.get(signature)
            if not values:
                continue
            active_values = {seen_at for seen_at in values if seen_at >= cutoff}
            if active_values:
                store[signature] = active_values
            else:
                store.pop(signature, None)

    def _extract_qso_datetime(self, data: Dict[str, str]) -> Optional[str]:
        timestamp_field = data.get("TIMESTAMP") or data.get("TIME")
        if timestamp_field:
            iso_ts = self._parse_timestamp(timestamp_field)
            if iso_ts:
                return iso_ts
        return self._build_qso_datetime(data.get("QSO_DATE"), data.get("TIME_ON"))

    @staticmethod
    def _build_qso_datetime(qso_date: Optional[str], time_on: Optional[str]) -> Optional[str]:
        if qso_date and time_on and len(qso_date) == 8 and len(time_on) >= 6:
            try:
                formatted = dt.datetime.strptime(
                    f"{qso_date}{time_on[:6]}", "%Y%m%d%H%M%S"
                )
                return formatted.strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                LOGGER.warning("Invalid date/time from N1MM: %s %s", qso_date, time_on)
        return None

    @staticmethod
    def _parse_timestamp(timestamp: str) -> Optional[str]:
        clean = timestamp.strip()

        # Try ISO parser first to support common forms with/without timezone and ms.
        try:
            iso_candidate = clean
            if iso_candidate.endswith("Z"):
                iso_candidate = iso_candidate[:-1] + "+00:00"
            parsed = dt.datetime.fromisoformat(iso_candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            else:
                parsed = parsed.astimezone(dt.timezone.utc)
            return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass

        for fmt in (
            "%Y-%m-%d %H:%M:%S %z",
            "%Y-%m-%d %H:%M:%S.%f %z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
        ):
            try:
                parsed = dt.datetime.strptime(clean, fmt)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=dt.timezone.utc)
                else:
                    parsed = parsed.astimezone(dt.timezone.utc)
                return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                continue
        LOGGER.warning("Unable to parse timestamp: %s", timestamp)
        return None

    @staticmethod
    def _normalize_band(band: Optional[str], freq: Optional[str]) -> Optional[str]:
        allowed = {
            "13cm",
            "23cm",
            "70cm",
            "2m",
            "6m",
            "10m",
            "12m",
            "15m",
            "17m",
            "20m",
            "30m",
            "40m",
            "60m",
            "80m",
            "160m",
        }

        def from_mhz(value: float) -> Optional[str]:
            ranges = [
                (2300, 2450, "13cm"),
                (1240, 1300, "23cm"),
                (420, 450, "70cm"),
                (144, 148, "2m"),
                (50, 54, "6m"),
                (28, 30, "10m"),
                (24, 25, "12m"),
                (21, 22, "15m"),
                (18, 19, "17m"),
                (14, 15, "20m"),
                (10, 11, "30m"),
                (7, 8, "40m"),
                (5, 6, "60m"),
                (3, 4, "80m"),
                (1.8, 2.1, "160m"),
            ]
            for low, high, label in ranges:
                if low <= value < high:
                    return label
            return None

        def parse_freq(text: str) -> Optional[float]:
            cleaned = text.strip()
            if not cleaned:
                return None
            if "." in cleaned and "," in cleaned:
                number = cleaned.replace(".", "").replace(",", ".")
            elif "," in cleaned:
                number = cleaned.replace(",", ".")
            else:
                number = cleaned
            try:
                return float(number)
            except ValueError:
                return None

        value = (band or "").strip()
        if value:
            lowercase = value.lower().replace(" ", "")
            if lowercase in allowed:
                return lowercase
            if lowercase.endswith("m"):
                candidate = lowercase
                if candidate in allowed:
                    return candidate
                try:
                    mhz = float(candidate[:-1])
                    result = from_mhz(mhz)
                    if result:
                        return result
                except ValueError:
                    pass
            try:
                mhz = float(value)
                result = from_mhz(mhz)
                if result:
                    return result
            except ValueError:
                    pass

        if freq:
            try:
                parsed_freq = parse_freq(freq)
                if parsed_freq is None:
                    return None
                freq_val = parsed_freq
                for scale in (1, 1_000, 1_000_000, 10, 100, 10_000, 100_000):
                    mhz = freq_val / scale
                    result = from_mhz(mhz)
                    if result:
                        return result
            except ValueError:
                pass
        return None

    @staticmethod
    def _normalize_mode(mode: Optional[str]) -> Optional[str]:
        if not mode:
            return None
        normalized = mode.strip().upper()
        mapped = {
            "USB": "SSB",
            "LSB": "SSB",
        }
        normalized = mapped.get(normalized, normalized)
        allowed = {"SSB", "CW", "FT8", "FT4", "DIGITAL", "RTTY", "SSTV", "DIGITALVOICE", "FM"}
        return normalized if normalized in allowed else None

    @staticmethod
    def _normalize_exchange(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = str(value).strip()
        return cleaned[:32] if cleaned else None

    @staticmethod
    def _resolve_exchange(
        data: Dict[str, str],
        primary_keys: tuple[str, ...],
        report_key: str,
        serial_key: str,
    ) -> Optional[str]:
        for key in primary_keys:
            value = data.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()

        parts: List[str] = []
        report = str(data.get(report_key) or "").strip()
        serial = str(data.get(serial_key) or "").strip()
        if report:
            parts.append(report)
        if serial and serial != "0":
            parts.append(serial)
        return " ".join(parts) if parts else None

    @staticmethod
    def _normalize_frequency(value: Optional[str], band_hint: Optional[str] = None) -> Optional[str]:
        if not value:
            return None
        raw = str(value).strip()
        if not raw:
            return None

        def parse_numeric(text: str) -> Optional[float]:
            cleaned = text.strip()
            if not cleaned:
                return None
            if "." in cleaned and "," in cleaned:
                number = cleaned.replace(".", "").replace(",", ".")
            elif "," in cleaned:
                number = cleaned.replace(",", ".")
            else:
                number = cleaned
            try:
                return float(number)
            except ValueError:
                return None

        numeric = parse_numeric(raw)
        if numeric is None:
            return None

        band_ranges = {
            "13cm": (2300, 2450),
            "23cm": (1240, 1300),
            "70cm": (420, 450),
            "2m": (144, 148),
            "6m": (50, 54),
            "10m": (28, 30),
            "12m": (24, 25),
            "15m": (21, 22),
            "17m": (18, 19),
            "20m": (14, 15),
            "30m": (10, 11),
            "40m": (7, 8),
            "60m": (5, 6),
            "80m": (3, 4),
            "160m": (1.8, 2.1),
        }

        candidates: List[float] = []
        for scale in (1, 1_000, 1_000_000, 10, 100, 10_000, 100_000):
            candidates.append(numeric / scale)

        chosen: Optional[float] = None
        band_lower, band_upper = band_ranges.get(band_hint or "", (None, None))
        if band_lower is not None and band_upper is not None:
            in_range = [
                c for c in candidates if band_lower <= c < band_upper
            ]
            if in_range:
                mid = (band_lower + band_upper) / 2
                chosen = min(in_range, key=lambda c: abs(c - mid))

        if chosen is None:
            in_any_band = [
                c
                for c in candidates
                if any(low <= c < high for low, high in band_ranges.values())
            ]
            if in_any_band:
                chosen = in_any_band[0]

        if chosen is None:
            plausible = [c for c in candidates if 0.1 <= c <= 2500]
            if plausible:
                chosen = plausible[0]
            else:
                return None

        khz = chosen * 1000
        formatted = f"{khz:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
        return formatted[:32]

    def _get_parser_for_profile(self) -> Callable[[Union[bytes, str]], Dict[str, str]]:
        profile = self.log_profile.get().strip().lower()
        if profile in {"wsjt-x/jtdx", "wsjtx", "jtdx"}:
            return self._parse_wsjtx_jtdx
        return UdpListener._parse_datagram

    @staticmethod
    def _parse_wsjtx_jtdx(data: Union[bytes, str]) -> Dict[str, str]:
        if isinstance(data, str):
            data = data.encode("latin-1", errors="ignore")

        try:
            reader = WsjtxDatagramReader(data)
            magic = reader.read_u32()
            if magic != WsjtxDatagramReader.MAGIC:
                return {}
            reader.read_u32()  # schema
            message_type = reader.read_u32()
            reader.read_utf8()  # client id

            if message_type != 5:  # QSO Logged; ignore Decode and all other messages.
                return {}

            reader.read_qdatetime()  # Date & Time Off
            call = reader.read_utf8()
            reader.read_utf8()  # DX grid, ignored unless awards need it later.
            frequency_hz = reader.read_u64()
            mode = reader.read_utf8()
            sent_report = reader.read_utf8()
            received_report = reader.read_utf8()
            reader.read_utf8()  # Tx power
            reader.read_utf8()  # Comments
            reader.read_utf8()  # Name
            time_on = reader.read_qdatetime()

            fields: Dict[str, str] = {
                "CALL": call,
                "FREQ": str(frequency_hz),
                "MODE": mode,
                "STX_STRING": sent_report,
                "SRX_STRING": received_report,
            }
            if time_on:
                fields["QSO_DATE"] = time_on.strftime("%Y%m%d")
                fields["TIME_ON"] = time_on.strftime("%H%M%S")
            return {key: value for key, value in fields.items() if value}
        except (IndexError, struct.error, ValueError) as exc:
            LOGGER.warning("Invalid or partial WSJT-X/JTDX datagram: %s", exc)
            return {}

    @staticmethod
    def _format_qso_summary(payload: Dict[str, Any]) -> str:
        date = payload.get("qsoDateTime", "-")
        band = payload.get("band", "-")
        mode = payload.get("mode", "-")
        call = payload.get("callsign", "-")
        dxcc = payload.get("dxcc")
        base = f"QSO enviado: {call} | {date} | {band} | {mode}"
        return f"{base} | DXCC {dxcc}" if dxcc else base

    def _log(self, message: str, debug_only: bool = False) -> None:
        if debug_only and not self.debug_var.get():
            return
        self._append_log(message)

    def _append_log(self, message: str) -> None:
        self.root.after(0, lambda: self._write_log(message))

    def _write_log(self, message: str) -> None:
        self.log_text.configure(state="normal")
        timestamp = utc_now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert("end", f"{timestamp} - {message}\n")
        self.log_text.configure(state="disabled")
        self.log_text.see("end")

    def _perform_logout(self) -> None:
        if self.udp_listener and self.udp_listener.is_running():
            self.udp_listener.stop()
            self.udp_listener = None
        self.diplomas = []
        self.selected_diploma_id = None
        self.diploma_combo.set("")
        self.diploma_combo["values"] = []
        self._update_login_state(False, "Desconectado")
        self.login_button.config(text="Login")
        self._log("Sesion cerrada por el usuario.")


def main() -> None:
    root = tk.Tk()
    app = MainWindow(root)
    try:
        root.mainloop()
    finally:
        if app.udp_listener and app.udp_listener.is_running():
            app.udp_listener.stop()


if __name__ == "__main__":
    main()
