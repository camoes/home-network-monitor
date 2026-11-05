"""Tests for device classification and DNS query parsing (no network access)."""

import tempfile
import unittest
from pathlib import Path

import classify
import collector


ROUTER_METRICS = """
# HELP router_connected_device_info Connected device metadata from the router; value is always 1.
# TYPE router_connected_device_info gauge
router_connected_device_info{mac="24:9E:7D:00:00:03",ip="192.0.2.27",name="dispositivo-12",device_type="desconocido",network="WLAN",port="DEV.WIFI.AP1",ssid="MI-RED-WIFI-2"} 1
router_connected_device_info{mac="00:00:5E:00:53:06",ip="192.0.2.73",name="dispositivo-7",device_type="desconocido",network="WLAN",port="DEV.WIFI.AP1",ssid="MI-RED-WIFI-2"} 1
router_connected_device_info{mac="58:11:22:00:00:04",ip="192.0.2.46",name="unknown",device_type="desconocido",network="LAN",port="LAN1",ssid=""} 1
"""


def querylog_entry(client="192.0.2.73", domain="example.com", answers=None, filtered=False):
    """Shape returned by AdGuard Home 0.107+ (/control/querylog)."""
    return {
        "client": client,
        "time": "2026-10-31T09:00:00.5+01:00",
        "question": {"name": domain, "type": "A", "class": "IN"},
        "answer": answers if answers is not None else [{"type": "A", "value": "93.184.216.34", "ttl": 60}],
        "reason": "FilteredBlackList" if filtered else "NotFilteredNotFound",
        "status": "NOERROR",
        "upstream": "",
    }


def legacy_querylog_entry():
    """Older AdGuard builds used capitalised keys; the parser accepts both."""
    return {
        "IP": "192.0.2.73",
        "T": "2026-10-31T09:00:00.5+01:00",
        "Question": {"Name": "example.com.", "Qtype": "A"},
        "Answer": [{"Type": "A", "Value": "93.184.216.34"}],
        "Result": {"IsFiltered": False},
    }


class RouterMetricsTests(unittest.TestCase):
    def test_parses_device_labels(self):
        devices = collector.parse_router_metrics(ROUTER_METRICS)
        self.assertEqual(len(devices), 3)
        self.assertEqual(devices[0]["name"], "dispositivo-12")
        self.assertEqual(devices[0]["ssid"], "MI-RED-WIFI-2")
        self.assertEqual(devices[2]["network"], "LAN")


class ClassificationTests(unittest.TestCase):
    def test_hostname_beats_vendor(self):
        info = classify.classify("24:9E:7D:00:00:03", "dispositivo-12", {}, {})
        self.assertEqual(info["device_type"], "aspirador")
        self.assertEqual(info["vendor"], "Roborock")

    def test_vendor_table_used_when_hostname_is_generic(self):
        info = classify.classify("58:11:22:00:00:04", "unknown", {}, {})
        self.assertEqual(info["vendor"], "ZTE")
        self.assertEqual(info["device_type"], "red")
        self.assertEqual(info["name"], "ZTE")

    def test_override_wins_over_everything(self):
        overrides = {"00:00:5E:00:53:05": {"mac": "00:00:5E:00:53:05", "name": "dispositivo-5", "device_type": "domótica"}}
        info = classify.classify("00:00:5E:00:53:05", "ESP_1234", {}, overrides)
        self.assertEqual(info["name"], "dispositivo-5")
        self.assertEqual(info["device_type"], "domótica")
        self.assertEqual(info["source"], "override")

    def test_unknown_device_is_labelled_honestly(self):
        info = classify.classify("00:00:5E:00:53:01", "unknown", {}, {})
        self.assertEqual(info["device_type"], "desconocido")

    def test_household_hostnames_from_this_lan(self):
        cases = {
            "HP5C83D8": "impresora",
            "Mac": "ordenador",
            "MacBookPro": "ordenador",
            "net_ac_A242": "domótica",
            "bosch-dishwasher-405090552": "electrodoméstico",
            "Pixel-6": "móvil",
        }
        for hostname, expected in cases.items():
            with self.subTest(hostname=hostname):
                info = classify.classify("00:00:5E:00:53:02", hostname, {}, {})
                self.assertEqual(info["device_type"], expected)


class DestinationTests(unittest.TestCase):
    def test_external_public_answer(self):
        self.assertEqual(collector.pick_destination(querylog_entry()), ("93.184.216.34", "external"))

    def test_private_answer_is_internal(self):
        entry = querylog_entry(answers=[{"Type": "A", "Value": "192.0.2.1"}])
        self.assertEqual(collector.pick_destination(entry), ("192.0.2.1", "internal"))

    def test_blocked_answer(self):
        entry = querylog_entry(answers=[{"Type": "A", "Value": "0.0.0.0"}])
        self.assertEqual(collector.pick_destination(entry), ("0.0.0.0", "blocked"))

    def test_cname_chain_uses_first_public_a_record(self):
        entry = querylog_entry(answers=[
            {"Type": "CNAME", "Value": "cdn.example.net."},
            {"Type": "A", "Value": "151.101.1.69"},
        ])
        self.assertEqual(collector.pick_destination(entry), ("151.101.1.69", "external"))

    def test_no_answer(self):
        self.assertEqual(collector.pick_destination(querylog_entry(answers=[])), ("", "none"))

    def test_filtered_reason_marks_blocked(self):
        entry = querylog_entry(answers=[], filtered=True)
        self.assertEqual(collector.pick_destination(entry), ("", "blocked"))
        self.assertTrue(collector.entry_filtered(entry))

    def test_legacy_capitalised_payload_still_parses(self):
        entry = legacy_querylog_entry()
        self.assertEqual(collector.entry_client(entry), "192.0.2.73")
        self.assertEqual(collector.entry_question(entry)["Name"], "example.com.")
        self.assertEqual(collector.pick_destination(entry), ("93.184.216.34", "external"))


class MetricsTests(unittest.TestCase):
    """The Prometheus endpoint must render even with an empty database."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.previous = collector.DB_PATH
        collector.DB_PATH = Path(self.tmp.name) / "netviz.db"
        collector._CONN = None

    def tearDown(self):
        if collector._CONN is not None:
            collector._CONN.close()
        collector._CONN = None
        collector.DB_PATH = self.previous
        self.tmp.cleanup()

    def test_metrics_render_without_data(self):
        text = collector.render_metrics()
        self.assertIn("# TYPE netviz_device_queries_total counter", text)
        self.assertIn("# TYPE netviz_destination_total counter", text)

    def test_tracker_detection(self):
        self.assertTrue(collector.is_tracker("app-measurement.com"))
        self.assertTrue(collector.is_tracker("samsungads.com"))
        self.assertTrue(collector.is_tracker("data.telemetry.example.net"))
        self.assertFalse(collector.is_tracker("wikipedia.org"))
        self.assertFalse(collector.is_tracker("github.com"))


class OuiTests(unittest.TestCase):
    def test_loads_ieee_csv(self):
        sample = Path("/tmp/oui_test.csv")
        sample.write_text(
            "Registry,Assignment,Organization Name,Organization Address\n"
            "MA-L,249E7D,Beijing Roborock Technology Co. Ltd.,Beijing\n",
            encoding="utf-8",
        )
        try:
            table = classify.load_oui(sample)
            self.assertEqual(table["249E7D"], "Beijing Roborock Technology Co. Ltd.")
            self.assertEqual(classify.vendor_for("24:9E:7D:00:00:03", table),
                             "Beijing Roborock Technology Co. Ltd.")
        finally:
            sample.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
