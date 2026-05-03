import datetime as dt
import struct
import unittest
from types import SimpleNamespace

from radioaward_bridge import MainWindow, UdpListener, WsjtxDatagramReader


def make_window() -> MainWindow:
    window = MainWindow.__new__(MainWindow)
    window.api_client = SimpleNamespace(api_key="12345678-test-api-key")
    window.selected_diploma_id = "diploma-test-id"
    return window


def pack_utf8(value: str) -> bytes:
    data = value.encode("utf-8")
    return struct.pack(">I", len(data)) + data


def julian_day(value: dt.date) -> int:
    a_value = (14 - value.month) // 12
    year = value.year + 4800 - a_value
    month = value.month + 12 * a_value - 3
    return (
        value.day
        + ((153 * month + 2) // 5)
        + 365 * year
        + year // 4
        - year // 100
        + year // 400
        - 32045
    )


def pack_qdatetime(value: dt.datetime) -> bytes:
    value_utc = value.astimezone(dt.timezone.utc)
    msecs = (
        value_utc.hour * 3_600_000
        + value_utc.minute * 60_000
        + value_utc.second * 1_000
        + value_utc.microsecond // 1_000
    )
    return struct.pack(">qIB", julian_day(value_utc.date()), msecs, 1)


def build_wsjtx_logged_packet(
    *,
    call: str,
    frequency_hz: int,
    mode: str,
    sent_report: str,
    received_report: str,
    time_on: dt.datetime,
    client_id: str,
) -> bytes:
    time_off = time_on + dt.timedelta(minutes=1)
    return b"".join(
        [
            struct.pack(">I", WsjtxDatagramReader.MAGIC),
            struct.pack(">I", 3),
            struct.pack(">I", 5),
            pack_utf8(client_id),
            pack_qdatetime(time_off),
            pack_utf8(call),
            pack_utf8("JM77"),
            struct.pack(">Q", frequency_hz),
            pack_utf8(mode),
            pack_utf8(sent_report),
            pack_utf8(received_report),
            pack_utf8("35"),
            pack_utf8(""),
            pack_utf8(""),
            pack_qdatetime(time_on),
        ]
    )


class RadioAwardBridgeTests(unittest.TestCase):
    def test_xml_samples_build_expected_payloads(self) -> None:
        window = make_window()
        cases = [
            {
                "name": "HRD FT4 over MFSK submode",
                "message": """<?xml version="1.0" encoding="utf-8"?>
<contactinfo>
  <app>HamRadioDeluxe</app>
  <timestamp>2026-05-03 19:48:49</timestamp>
  <band>14</band>
  <txfreq>14082000</txfreq>
  <mode>MFSK</mode>
  <submode>FT4</submode>
  <call>II9IGJ</call>
  <snt>-10</snt>
  <rcv>-20</rcv>
</contactinfo>""",
                "expected": {
                    "callsign": "II9IGJ",
                    "qsoDateTime": "2026-05-03T19:48:49Z",
                    "band": "20m",
                    "frequency": "14.082,00",
                    "mode": "FT4",
                    "rstSent": "-10",
                    "rstRcvd": "-20",
                },
            },
            {
                "name": "HRD DMR as DIGITALVOICE",
                "message": """<?xml version="1.0" encoding="utf-8"?>
<contactinfo>
  <app>HamRadioDeluxe</app>
  <timestamp>2026-05-03 20:01:02</timestamp>
  <band>145</band>
  <txfreq>145650000</txfreq>
  <mode>DIGITAL VOICE</mode>
  <submode>DMR</submode>
  <call>EA3XYZ</call>
  <snt>59</snt>
  <rcv>59</rcv>
</contactinfo>""",
                "expected": {
                    "callsign": "EA3XYZ",
                    "qsoDateTime": "2026-05-03T20:01:02Z",
                    "band": "2m",
                    "frequency": "145.650,00",
                    "mode": "DIGITALVOICE",
                    "rstSent": "59",
                    "rstRcvd": "59",
                },
            },
            {
                "name": "N1MM USB mapped to SSB",
                "message": """<?xml version="1.0" encoding="utf-8"?>
<contactinfo>
  <app>N1MM Logger+</app>
  <timestamp>2026-05-03 18:15:00</timestamp>
  <band>14</band>
  <txfreq>14250000</txfreq>
  <mode>USB</mode>
  <call>K1ABC</call>
  <snt>59</snt>
  <rcv>59</rcv>
</contactinfo>""",
                "expected": {
                    "callsign": "K1ABC",
                    "qsoDateTime": "2026-05-03T18:15:00Z",
                    "band": "20m",
                    "frequency": "14.250,00",
                    "mode": "SSB",
                    "rstSent": "59",
                    "rstRcvd": "59",
                },
            },
            {
                "name": "Log4OM contact root with FT8",
                "message": """<?xml version="1.0" encoding="utf-8"?>
<contact>
  <app>Log4OM</app>
  <timestamp>2026-05-03T21:22:33</timestamp>
  <band>7</band>
  <txfreq>7074000</txfreq>
  <mode>MFSK</mode>
  <submode>FT8</submode>
  <call>DL1LOG</call>
  <snt>-08</snt>
  <rcv>-12</rcv>
</contact>""",
                "expected": {
                    "callsign": "DL1LOG",
                    "qsoDateTime": "2026-05-03T21:22:33Z",
                    "band": "40m",
                    "frequency": "7.074,00",
                    "mode": "FT8",
                    "rstSent": "-08",
                    "rstRcvd": "-12",
                },
            },
            {
                "name": "Unsupported digital submode omitted",
                "message": """<?xml version="1.0" encoding="utf-8"?>
<contactinfo>
  <app>HamRadioDeluxe</app>
  <timestamp>2026-05-03 22:10:11</timestamp>
  <band>14</band>
  <txfreq>14078000</txfreq>
  <mode>MFSK</mode>
  <submode>JS8</submode>
  <call>EA3JS8</call>
  <snt>-05</snt>
  <rcv>-07</rcv>
</contactinfo>""",
                "expected": {
                    "callsign": "EA3JS8",
                    "qsoDateTime": "2026-05-03T22:10:11Z",
                    "band": "20m",
                    "frequency": "14.078,00",
                    "rstSent": "-05",
                    "rstRcvd": "-07",
                },
                "missing_keys": {"mode"},
            },
        ]

        for case in cases:
            with self.subTest(case=case["name"]):
                parsed = UdpListener._parse_datagram(case["message"])
                payload = window._build_contact_payload(parsed)

                self.assertIsNotNone(payload)
                self.assertEqual(payload["apiKey"], "12345678-test-api-key")
                self.assertEqual(payload["diplomaId"], "diploma-test-id")
                for key, expected_value in case["expected"].items():
                    self.assertEqual(payload.get(key), expected_value)
                for key in case.get("missing_keys", set()):
                    self.assertNotIn(key, payload)

    def test_wsjtx_and_jtdx_logged_packets_build_expected_payloads(self) -> None:
        window = make_window()
        base_time = dt.datetime(2026, 5, 3, 19, 48, 49, tzinfo=dt.timezone.utc)
        cases = [
            {
                "name": "WSJT-X FT8",
                "packet": build_wsjtx_logged_packet(
                    call="K1WSJ",
                    frequency_hz=14_074_000,
                    mode="FT8",
                    sent_report="-09",
                    received_report="-14",
                    time_on=base_time,
                    client_id="WSJT-X",
                ),
                "expected": {
                    "callsign": "K1WSJ",
                    "qsoDateTime": "2026-05-03T19:48:49Z",
                    "band": "20m",
                    "frequency": "14.074,00",
                    "mode": "FT8",
                    "rstSent": "-09",
                    "rstRcvd": "-14",
                },
            },
            {
                "name": "JTDX FT4",
                "packet": build_wsjtx_logged_packet(
                    call="EA3JTD",
                    frequency_hz=7_047_500,
                    mode="FT4",
                    sent_report="-07",
                    received_report="-11",
                    time_on=base_time + dt.timedelta(minutes=5),
                    client_id="JTDX",
                ),
                "expected": {
                    "callsign": "EA3JTD",
                    "qsoDateTime": "2026-05-03T19:53:49Z",
                    "band": "40m",
                    "frequency": "7.047,50",
                    "mode": "FT4",
                    "rstSent": "-07",
                    "rstRcvd": "-11",
                },
            },
        ]

        for case in cases:
            with self.subTest(case=case["name"]):
                parsed = MainWindow._parse_wsjtx_jtdx(case["packet"])
                payload = window._build_contact_payload(parsed)

                self.assertIsNotNone(payload)
                for key, expected_value in case["expected"].items():
                    self.assertEqual(payload.get(key), expected_value)

    def test_non_qso_wsjtx_packet_is_ignored(self) -> None:
        packet = b"".join(
            [
                struct.pack(">I", WsjtxDatagramReader.MAGIC),
                struct.pack(">I", 3),
                struct.pack(">I", 1),
                pack_utf8("WSJT-X"),
            ]
        )
        self.assertEqual(MainWindow._parse_wsjtx_jtdx(packet), {})


if __name__ == "__main__":
    unittest.main()
