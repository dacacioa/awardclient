import datetime as dt
import json
from pathlib import Path
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from radioaward_bridge import ApiClient, MainWindow, UdpListener, WsjtxDatagramReader


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


def build_qlog_qso_packet(
    *,
    operation: str,
    adif_value: str,
    qso_type: str = "adif",
) -> bytes:
    return json.dumps(
        {
            "appid": "QLog",
            "logid": "{test-log-id}",
            "msgtype": "qso",
            "time": 1770000000000,
            "data": {
                "operation": operation,
                "rowid": 355,
                "type": qso_type,
                "value": adif_value,
            },
        }
    ).encode("utf-8")


class RadioAwardBridgeTests(unittest.TestCase):
    def test_contact_payload_is_rejected_when_required_contract_fields_are_missing(self) -> None:
        window = make_window()

        payload = window._build_contact_payload(
            {
                "CALL": "EA3MISS",
                "BAND": "20m",
                "MODE": "MFSK",
                "SUBMODE": "JS8",
            }
        )

        self.assertIsNone(payload)

    def test_api_client_copies_ca_bundle_to_stable_user_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            source = tmp_path / "cacert-source.pem"
            source.write_text("test-ca", encoding="utf-8")
            home = tmp_path / "home"
            home.mkdir()

            session = mock.Mock()

            with mock.patch("radioaward_bridge.requests.certs.where", return_value=str(source)):
                with mock.patch("radioaward_bridge.requests.Session", return_value=session):
                    with mock.patch("radioaward_bridge.Path.home", return_value=home):
                        client = ApiClient("https://example.test")

            stable_bundle = home / ".hamactivity_bridge_cacert.pem"
            self.assertEqual(client._ca_bundle_path, str(stable_bundle))
            self.assertEqual(session.verify, str(stable_bundle))
            self.assertEqual(stable_bundle.read_text(encoding="utf-8"), "test-ca")

    def test_api_client_retries_after_tls_invalid_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            source = tmp_path / "cacert-source.pem"
            source.write_text("test-ca", encoding="utf-8")
            home = tmp_path / "home"
            home.mkdir()

            first_session = mock.Mock()
            second_session = mock.Mock()
            response = mock.Mock(status_code=200)
            response.json.return_value = {"operator": {}, "diplomas": []}
            first_session.post.side_effect = OSError(
                "Could not find a suitable TLS CA certificate bundle, invalid path: C:\\temp\\_MEI123\\cacert.pem"
            )
            second_session.post.return_value = response

            with mock.patch("radioaward_bridge.requests.certs.where", return_value=str(source)):
                with mock.patch(
                    "radioaward_bridge.requests.Session",
                    side_effect=[first_session, second_session],
                ):
                    with mock.patch("radioaward_bridge.Path.home", return_value=home):
                        client = ApiClient("https://example.test", "12345678")
                        data = client.login()

            self.assertEqual(data, {"operator": {}, "diplomas": []})
            self.assertEqual(first_session.post.call_count, 1)
            self.assertEqual(second_session.post.call_count, 1)

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

                if case.get("missing_keys"):
                    self.assertIsNone(payload)
                    continue
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

    def test_qlog_qso_packets_build_expected_payloads(self) -> None:
        window = make_window()
        cases = [
            {
                "name": "QLog insert packet with ADIF mode and timestamp",
                "packet": build_qlog_qso_packet(
                    operation="insert",
                    adif_value=(
                        "<call:6>EA3QLO<qso_date:8:D>20260503<time_on:6:T>194849"
                        "<freq:8:N>14.07400<band:3>20m<mode:3>FT8"
                        "<rst_sent:3>-08<rst_rcvd:3>-12<country:5>Spain<dxcc:3>281<eor>"
                    ),
                ),
                "expected": {
                    "callsign": "EA3QLO",
                    "qsoDateTime": "2026-05-03T19:48:49Z",
                    "band": "20m",
                    "frequency": "14.074,00",
                    "mode": "FT8",
                    "rstSent": "-08",
                    "rstRcvd": "-12",
                    "country": "Spain",
                    "dxcc": "281",
                },
            },
            {
                "name": "QLog insert packet preserves base SSB mode when submode is USB",
                "packet": json.dumps(
                    {
                        "appid": "QLog",
                        "data": {
                            "operation": "insert",
                            "rowid": 6,
                            "type": "adif",
                            "value": (
                                "<call:6>EA3IMR<rst_sent:2>59<rst_rcvd:2>59<freq:5>7.074"
                                "<band:3>40m<mode:3>SSB<submode:3>USB"
                                "<qso_date:8>20260508<time_on:6>171559<eor>"
                            ),
                        },
                        "logid": "{6f4ce8da-1e0d-4cc6-a9a0-848147079d90}",
                        "msgtype": "qso",
                        "time": 1778260559234,
                    }
                ).encode("utf-8"),
                "expected": {
                    "callsign": "EA3IMR",
                    "qsoDateTime": "2026-05-08T17:15:59Z",
                    "band": "40m",
                    "frequency": "7.074,00",
                    "mode": "SSB",
                    "rstSent": "59",
                    "rstRcvd": "59",
                },
            },
            {
                "name": "QLog insert packet collapses submode to DIGITALVOICE",
                "packet": build_qlog_qso_packet(
                    operation="insert",
                    adif_value=(
                        "<call:6>EA3DMR<qso_date:8:D>20260503<time_on:6:T>201500"
                        "<freq:9:N>145.65000<band:2>2m<mode:12>DIGITALVOICE"
                        "<submode:3>DMR<rst_sent:2>59<rst_rcvd:2>59<eor>"
                    ),
                ),
                "expected": {
                    "callsign": "EA3DMR",
                    "qsoDateTime": "2026-05-03T20:15:00Z",
                    "band": "2m",
                    "frequency": "145.650,00",
                    "mode": "DIGITALVOICE",
                    "rstSent": "59",
                    "rstRcvd": "59",
                },
            },
        ]

        for case in cases:
            with self.subTest(case=case["name"]):
                parsed = MainWindow._parse_qlog(case["packet"])
                payload = window._build_contact_payload(parsed)

                self.assertIsNotNone(payload)
                for key, expected_value in case["expected"].items():
                    self.assertEqual(payload.get(key), expected_value)

    def test_qlog_non_supported_packets_are_ignored(self) -> None:
        update_packet = build_qlog_qso_packet(
            operation="update",
            adif_value="<call:6>EA3UPD<qso_date:8:D>20260503<time_on:6:T>194849<eor>",
        )
        delete_packet = build_qlog_qso_packet(
            operation="delete",
            adif_value="<call:6>EA3DEL<qso_date:8:D>20260503<time_on:6:T>194849<eor>",
        )
        wrong_type_packet = build_qlog_qso_packet(
            operation="insert",
            adif_value="<call:6>EA3BAD<eor>",
            qso_type="json",
        )
        non_qso_packet = json.dumps(
            {"appid": "QLog", "msgtype": "dxspot", "data": {"call": "EA3DX"}}
        ).encode("utf-8")

        self.assertEqual(MainWindow._parse_qlog(update_packet), {})
        self.assertEqual(MainWindow._parse_qlog(delete_packet), {})
        self.assertEqual(MainWindow._parse_qlog(wrong_type_packet), {})
        self.assertEqual(MainWindow._parse_qlog(non_qso_packet), {})

    def test_regression_samples_cover_transport_and_timestamp_variants(self) -> None:
        window = make_window()
        cases = [
            {
                "name": "N1MM tab-delimited with qso_date and time_on fallback",
                "message": (
                    "CALL=EA3N1M\tBAND=14\tFREQ=14074000\tMODE=RTTY\t"
                    "QSO_DATE=20260503\tTIME_ON=194849\tSNT=599\tRCV=579"
                ),
                "expected": {
                    "callsign": "EA3N1M",
                    "qsoDateTime": "2026-05-03T19:48:49Z",
                    "band": "20m",
                    "frequency": "14.074,00",
                    "mode": "RTTY",
                    "rstSent": "599",
                    "rstRcvd": "579",
                },
            },
            {
                "name": "HRD timestamp with milliseconds and utc offset",
                "message": """<?xml version="1.0" encoding="utf-8"?>
<contactinfo>
  <app>HamRadioDeluxe</app>
  <timestamp>2026-05-03 21:48:49.250 +0200</timestamp>
  <band>14</band>
  <txfreq>14074000</txfreq>
  <mode>MFSK</mode>
  <submode>FT8</submode>
  <call>EA3UTC</call>
  <snt>-03</snt>
  <rcv>-09</rcv>
</contactinfo>""",
                "expected": {
                    "callsign": "EA3UTC",
                    "qsoDateTime": "2026-05-03T19:48:49Z",
                    "band": "20m",
                    "frequency": "14.074,00",
                    "mode": "FT8",
                    "rstSent": "-03",
                    "rstRcvd": "-09",
                },
            },
            {
                "name": "RXFREQ fallback when FREQ is absent",
                "message": """<?xml version="1.0" encoding="utf-8"?>
<contact>
  <app>Log4OM</app>
  <timestamp>2026-05-03T09:10:11Z</timestamp>
  <band>7</band>
  <rxfreq>7074500</rxfreq>
  <mode>FM</mode>
  <call>EA3RXF</call>
  <snt>59</snt>
  <rcv>59</rcv>
</contact>""",
                "expected": {
                    "callsign": "EA3RXF",
                    "qsoDateTime": "2026-05-03T09:10:11Z",
                    "band": "40m",
                    "frequency": "7.074,50",
                    "mode": "FM",
                    "rstSent": "59",
                    "rstRcvd": "59",
                },
            },
            {
                "name": "Unsupported hrd submode keeps payload but drops mode",
                "message": """<?xml version="1.0" encoding="utf-8"?>
<contactinfo>
  <app>HamRadioDeluxe</app>
  <timestamp>2026-05-03 12:00:01</timestamp>
  <band>14</band>
  <txfreq>14078000</txfreq>
  <mode>MFSK</mode>
  <submode>Q65</submode>
  <call>EA3Q65</call>
  <snt>-15</snt>
  <rcv>-18</rcv>
</contactinfo>""",
                "expected": {
                    "callsign": "EA3Q65",
                    "qsoDateTime": "2026-05-03T12:00:01Z",
                    "band": "20m",
                    "frequency": "14.078,00",
                    "rstSent": "-15",
                    "rstRcvd": "-18",
                },
                "missing_keys": {"mode"},
            },
            {
                "name": "N1MM digital voice collapsed from submode",
                "message": """<?xml version="1.0" encoding="utf-8"?>
<contactinfo>
  <app>N1MM Logger+</app>
  <timestamp>2026-05-03T16:20:30Z</timestamp>
  <band>145</band>
  <txfreq>145675000</txfreq>
  <mode>DIGITALVOICE</mode>
  <submode>DSTAR</submode>
  <call>EA3DVS</call>
  <snt>59</snt>
  <rcv>59</rcv>
</contactinfo>""",
                "expected": {
                    "callsign": "EA3DVS",
                    "qsoDateTime": "2026-05-03T16:20:30Z",
                    "band": "2m",
                    "frequency": "145.675,00",
                    "mode": "DIGITALVOICE",
                    "rstSent": "59",
                    "rstRcvd": "59",
                },
            },
        ]

        for case in cases:
            with self.subTest(case=case["name"]):
                parsed = UdpListener._parse_datagram(case["message"])
                payload = window._build_contact_payload(parsed)

                if case.get("missing_keys"):
                    self.assertIsNone(payload)
                    continue
                self.assertIsNotNone(payload)
                for key, expected_value in case["expected"].items():
                    self.assertEqual(payload.get(key), expected_value)
                for key in case.get("missing_keys", set()):
                    self.assertNotIn(key, payload)


if __name__ == "__main__":
    unittest.main()
