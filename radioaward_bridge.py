#!/usr/bin/env python3
"""
README
------
1) Requiere Python 3.12+ y la libreria requests: `pip install requests`.
2) Ejecute `python radioaward_bridge.py` (opcionalmente cree un venv antes).
3) La app almacena la URL base, API key y puerto UDP en un JSON dentro de la
   carpeta del usuario, por lo que no necesita variables de entorno adicionales.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
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
    "base_url": "https://RADIOAWARD_HOST",
    "api_key": "",
    "udp_port": 9091,
    "log_profile": "N1MM",
    "debug": False,
}


class SettingsManager:
    """Persist GUI preferences in a JSON file under the user profile."""

    def __init__(self, filename: Optional[Path] = None) -> None:
        config_name = filename or (Path.home() / ".radioaward_bridge_settings.json")
        self.path = config_name

    def load(self) -> Dict[str, Any]:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                LOGGER.debug("Loaded settings from %s", self.path)
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
    """Thin wrapper around the RadioAward REST API."""

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
    ) -> None:
        self.port = port
        self.callback = callback
        self.error_callback = error_callback
        self.log_callback = log_callback
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

            payload = data.decode("utf-8", errors="ignore").strip()
            if not payload:
                continue

            LOGGER.debug("Datagram received: %s", payload)
            if self.log_callback:
                self.log_callback(f"UDP recibido: {payload}")
            parsed = self._parse_datagram(payload)
            if parsed and parsed.get("CALL", "").strip():
                self.callback(parsed)

        try:
            sock.close()
        except OSError:
            pass

    @staticmethod
    def _parse_datagram(text: str) -> Dict[str, str]:
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

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("RadioAward Bridge para N1MM")

        self.settings_manager = SettingsManager()
        settings = self.settings_manager.load()
        self.api_client = ApiClient(settings["base_url"], settings["api_key"])
        self.udp_listener: Optional[UdpListener] = None
        self.diplomas: List[Diploma] = []
        self.selected_diploma_id: Optional[str] = None
        self.qso_counter = 0
        self.is_logged_in = False
        self.log_profile = tk.StringVar(value=settings.get("log_profile", "N1MM"))
        self.debug_var = tk.BooleanVar(value=settings.get("debug", False))

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
        ttk.Entry(settings_frame, textvariable=self.base_url_var).grid(
            row=0, column=1, sticky="ew"
        )

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
        ttk.Entry(settings_frame, textvariable=self.udp_port_var, width=10).grid(
            row=2, column=1, sticky="w"
        )
        ttk.Checkbutton(
            settings_frame, text="Debug", variable=self.debug_var
        ).grid(row=2, column=2, padx=4, sticky="w")


        # Login frame
        login_frame = ttk.LabelFrame(self.root, text="Operador")
        login_frame.grid(row=1, column=0, sticky="ew", **padding)
        login_frame.columnconfigure(1, weight=1)

        self.login_status_label = tk.Label(
            login_frame, text="Estado: Desconocido", bg="orange", fg="white"
        )
        self.login_status_label.grid(row=0, column=0, columnspan=3, sticky="ew", pady=2)

        self.login_button = ttk.Button(
            login_frame, text="Login", command=self.handle_login_logout
        )
        self.login_button.grid(row=1, column=0, padx=4, sticky="w")

        ttk.Label(login_frame, text="Diploma:").grid(row=1, column=1, sticky="e")
        self.diplomas_var = tk.StringVar()
        self.diploma_combo = ttk.Combobox(
            login_frame, textvariable=self.diplomas_var, state="readonly"
        )
        self.diploma_combo.grid(row=1, column=2, sticky="ew")
        self.diploma_combo.bind("<<ComboboxSelected>>", self._on_diploma_selected)

        ttk.Label(login_frame, text="Log:").grid(row=2, column=0, sticky="w", pady=(4, 0))
        self.log_profile_combo = ttk.Combobox(
            login_frame,
            values=["N1MM"],
            state="readonly",
            textvariable=self.log_profile,
        )
        self.log_profile_combo.grid(row=2, column=1, columnspan=2, sticky="ew", pady=(4, 0))
        self.log_profile_combo.set(self.log_profile.get())

        # UDP frame
        udp_frame = ttk.LabelFrame(self.root, text="Pasarela UDP")
        udp_frame.grid(row=2, column=0, sticky="ew", **padding)
        udp_frame.columnconfigure(0, weight=1)

        self.capture_button = ttk.Button(
            udp_frame, text="Iniciar captura", command=self.toggle_capture, state="disabled"
        )
        self.capture_button.grid(row=0, column=0, sticky="ew")

        # Status frame
        status_frame = ttk.LabelFrame(self.root, text="Estado de envio")
        status_frame.grid(row=3, column=0, sticky="ew", **padding)
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
        log_frame.grid(row=4, column=0, sticky="nsew", **padding)
        self.root.rowconfigure(4, weight=1)
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log_text = tk.Text(log_frame, height=12, state="disabled")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text["yscrollcommand"] = scrollbar.set

        self.root.after(100, self._ensure_udp_listener_running)

    def save_settings(self) -> None:
        old_port = self.udp_listener.port if self.udp_listener else None
        settings = {
            "base_url": self.base_url_var.get().strip(),
            "api_key": self.api_key_var.get().strip(),
            "udp_port": self.udp_port_var.get(),
            "log_profile": self.log_profile.get(),
            "debug": bool(self.debug_var.get()),
        }
        try:
            self.settings_manager.save(settings)
            self.api_client.set_base_url(settings["base_url"])
            self.api_client.set_api_key(settings["api_key"])
            self.log_profile.set(settings["log_profile"])
            if settings["udp_port"] != old_port:
                if self.udp_listener and self.udp_listener.is_running():
                    self.udp_listener.stop()
                    self.udp_listener = None
                self._start_udp_listener(settings["udp_port"])
            messagebox.showinfo("Ajustes", "Ajustes guardados correctamente.")
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
            self.diploma_combo.current(0)
            self.selected_diploma_id = diplomas[0].id
        else:
            self.diploma_combo.set("")
            self.selected_diploma_id = None
        self._update_login_state(True, f"Conectado como {operator.get('displayName')}")
        self._log(f"Login OK: {operator.get('callsign')} ({operator.get('username')})")
        self.login_button.config(text="Logout")
        self._refresh_capture_button_state()

    def _on_login_error(self, exc: Exception) -> None:
        self._set_login_button_state(True)
        self._update_login_state(False, "Error de login")
        messagebox.showerror("Login", str(exc))
        self._log(f"Login error: {exc}")
        self.login_button.config(text="Login")
        self._refresh_capture_button_state()

    def _update_login_state(self, ok: bool, text: str) -> None:
        color = "green" if ok else "red"
        self.login_status_label.config(text=text, bg=color)
        self.is_logged_in = ok

    def _on_diploma_selected(self, _event: Any) -> None:
        idx = self.diploma_combo.current()
        if idx >= 0 and idx < len(self.diplomas):
            self.selected_diploma_id = self.diplomas[idx].id
        self._refresh_capture_button_state()

    def _refresh_capture_button_state(self) -> None:
        running = bool(self.udp_listener and self.udp_listener.is_running())
        self.capture_button["state"] = "normal"
        self.capture_button.config(text="Detener captura" if running else "Iniciar captura")

    def toggle_capture(self) -> None:
        if self.udp_listener and self.udp_listener.is_running():
            self.udp_listener.stop()
            self.udp_listener = None
            self._refresh_capture_button_state()
            return

        self._start_udp_listener(self.udp_port_var.get())

    def _start_udp_listener(self, port: int) -> None:
        self.udp_listener = UdpListener(
            port,
            self._handle_incoming_qso,
            error_callback=self._handle_udp_error,
            log_callback=lambda msg: self._log(msg, debug_only=True),
        )
        self.udp_listener.start()
        self._refresh_capture_button_state()

    def _ensure_udp_listener_running(self) -> None:
        if not (self.udp_listener and self.udp_listener.is_running()):
            self._start_udp_listener(self.udp_port_var.get())
        else:
            self._refresh_capture_button_state()

    def _handle_udp_error(self, message: str) -> None:
        def _notify() -> None:
            messagebox.showerror("UDP", message)
            self.udp_listener = None
            self._refresh_capture_button_state()

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
        except Exception as exc:
            LOGGER.exception("Error sending contact: %s", exc)
            self.root.after(
                0,
                lambda: self.last_error_var.set(
                    f"{utc_now().strftime('%Y-%m-%dT%H:%M:%SZ')} - {exc}"
                ),
            )
            self._log(f"[{timestamp}] Error: {exc}")

    def _build_contact_payload(self, data: Dict[str, str]) -> Optional[Dict[str, Any]]:
        if not (self.api_client.api_key and self.selected_diploma_id):
            return None

        call = data.get("CALL", "").strip().upper()
        if not call:
            return None

        qso_dt = self._extract_qso_datetime(data)

        payload: Dict[str, Any] = {
            "apiKey": self.api_client.api_key,
            "diplomaId": self.selected_diploma_id,
            "callsign": call,
            "qsoDateTime": qso_dt,
        }

        band_value = self._normalize_band(
            data.get("BAND"),
            data.get("FREQ") or data.get("RXFREQ") or data.get("TXFREQ"),
        )
        if band_value:
            payload["band"] = band_value

        if mode := self._normalize_mode(data.get("MODE")):
            payload["mode"] = mode

        freq_value = self._normalize_frequency(
            data.get("FREQ") or data.get("RXFREQ") or data.get("TXFREQ")
        )
        if freq_value:
            payload["frequency"] = freq_value

        country_value = data.get("COUNTRY") or data.get("COUNTRYPREFIX")
        if country_value:
            payload["country"] = country_value

        dxcc_value = data.get("DXCC")
        if dxcc_value:
            payload["dxcc"] = dxcc_value

        return payload

    def _extract_qso_datetime(self, data: Dict[str, str]) -> str:
        timestamp_field = data.get("TIMESTAMP") or data.get("TIME")
        if timestamp_field:
            iso_ts = self._parse_timestamp(timestamp_field)
            if iso_ts:
                return iso_ts
        return self._build_qso_datetime(data.get("QSO_DATE"), data.get("TIME_ON"))

    @staticmethod
    def _build_qso_datetime(qso_date: Optional[str], time_on: Optional[str]) -> str:
        now = utc_now()
        if qso_date and time_on and len(qso_date) == 8 and len(time_on) >= 6:
            try:
                formatted = dt.datetime.strptime(
                    f"{qso_date}{time_on[:6]}", "%Y%m%d%H%M%S"
                )
                return formatted.strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                LOGGER.warning("Invalid date/time from N1MM: %s %s", qso_date, time_on)
        return now.strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _parse_timestamp(timestamp: str) -> Optional[str]:
        clean = timestamp.strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                parsed = dt.datetime.strptime(clean, fmt)
                return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                continue
        LOGGER.warning("Unable to parse timestamp: %s", timestamp)
        return None

    @staticmethod
    def _normalize_band(band: Optional[str], freq: Optional[str]) -> Optional[str]:
        allowed = {"10m", "12m", "15m", "17m", "20m", "30m", "40m", "80m"}

        def from_mhz(value: float) -> Optional[str]:
            ranges = [
                (28, 30, "10m"),
                (24, 25, "12m"),
                (21, 22, "15m"),
                (18, 19, "17m"),
                (14, 15, "20m"),
                (10, 11, "30m"),
                (7, 8, "40m"),
                (3, 4, "80m"),
            ]
            for low, high, label in ranges:
                if low <= value < high:
                    return label
            return None

        value = (band or "").strip()
        if value:
            lowercase = value.lower()
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
                freq_val = float(freq)
                for scale in (1_000_000, 100_000, 10_000, 1_000, 100, 10, 1):
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
        allowed = {"SSB", "CW", "FT8", "FT4", "RTTY", "SSTV"}
        return normalized if normalized in allowed else None

    @staticmethod
    def _normalize_frequency(value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        freq = str(value).strip()
        if not freq:
            return None
        return freq[:32]

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
        self.diplomas = []
        self.selected_diploma_id = None
        self.diploma_combo.set("")
        self.diploma_combo["values"] = []
        self._update_login_state(False, "Desconectado")
        self.login_button.config(text="Login")
        self._refresh_capture_button_state()
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
