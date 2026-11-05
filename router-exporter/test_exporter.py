import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import exporter


WAN_XML = b"""<?xml version=\"1.0\"?>
<ajax_response_xml_root>
  <IF_ERRORSTR>SUCC</IF_ERRORSTR>
  <ID_WAN_COMFIG>
    <Instance>
      <ParameterName>WANCName</ParameterName><ParameterValue>FTTH-DHCP-TV</ParameterValue>
      <ParameterName>ConnStatus</ParameterName><ParameterValue>Disconnected</ParameterValue>
      <ParameterName>RxBytes</ParameterName><ParameterValue>0</ParameterValue>
    </Instance>
    <Instance>
      <ParameterName>WANCName</ParameterName><ParameterValue>FTTH-Data</ParameterValue>
      <ParameterName>ConnStatus</ParameterName><ParameterValue>Connected</ParameterValue>
      <ParameterName>RxBytes</ParameterName><ParameterValue>2658778925</ParameterValue>
      <ParameterName>TxBytes</ParameterName><ParameterValue>1614684887</ParameterValue>
      <ParameterName>RxPackets</ParameterName><ParameterValue>47865403</ParameterValue>
      <ParameterName>TxPackets</ParameterName><ParameterValue>26008010</ParameterValue>
      <ParameterName>ErrorsReceived</ParameterName><ParameterValue>0</ParameterValue>
      <ParameterName>ErrorsSent</ParameterName><ParameterValue>0</ParameterValue>
    </Instance>
  </ID_WAN_COMFIG>
</ajax_response_xml_root>"""

DEVICE_XML = b"""<?xml version=\"1.0\"?>
<ajax_response_xml_root>
  <IF_ERRORSTR>SUCC</IF_ERRORSTR>
  <OBJ_ACCESSDEV_ID>
    <Instance>
      <ParameterName>MACAddress</ParameterName><ParameterValue>00:00:5E:00:53:05</ParameterValue>
      <ParameterName>IPAddress</ParameterName><ParameterValue>192.0.2.42</ParameterValue>
      <ParameterName>HostName</ParameterName><ParameterValue>dispositivo-13</ParameterValue>
      <ParameterName>IconType</ParameterName><ParameterValue>laptop</ParameterValue>
      <ParameterName>Active</ParameterName><ParameterValue>1</ParameterValue>
      <ParameterName>AliasName</ParameterName><ParameterValue>LAN1</ParameterValue>
    </Instance>
  </OBJ_ACCESSDEV_ID>
</ajax_response_xml_root>"""


class FakeRouterClient(exporter.ZTEClient):
    def login(self):
        self.logged_in = True

    def _request(self, path, data=None):
        if "_type=menuData" in path:
            return WAN_XML
        return b"<html>view ready</html>"

    def connected_devices(self):
        return [{"mac":"00:00:5E:00:53:05", "ip":"192.0.2.42", "name":"dispositivo-13", "device_type":"portátil", "network":"LAN", "port":"LAN1", "ssid":""}]


class FakeDeviceClient(exporter.ZTEClient):
    def _request(self, path, data=None):
        if "_type=menuData" in path:
            return DEVICE_XML
        return b"<html>view ready</html>"


class RouterExporterTests(unittest.TestCase):
    def setUp(self):
        exporter._ROUTER_CLIENT = None
        exporter._ROUTER_CONFIG_KEY = None
        exporter._RETRY_AFTER = 0.0
        exporter._FAILURE_COUNT = 0

    def test_unconfigured_exporter_does_not_attempt_router_login(self):
        exporter.CONFIG_FILE = Path("/path/that/does/not/exist/router.env")
        metrics = exporter.render_metrics()
        self.assertIn("router_exporter_configured 0", metrics)
        self.assertIn("router_exporter_scrape_success 0", metrics)
        self.assertNotIn("password", metrics.lower())

    def test_selects_active_ftth_data_counters(self):
        client = FakeRouterClient({
            "ROUTER_URL": "http://127.0.0.1",
            "ROUTER_USERNAME": "admin",
            "ROUTER_PASSWORD": "not-a-real-password",
            "ROUTER_WAN_NAME": "FTTH-Data",
        })
        counters = client.wan_counters()
        self.assertEqual(counters["up"], 1)
        self.assertEqual(counters["rx_bytes"], 2658778925)
        self.assertEqual(counters["tx_bytes"], 1614684887)
        self.assertEqual(counters["rx_packets"], 47865403)
        self.assertEqual(counters["tx_packets"], 26008010)

    def test_parses_device_inventory_and_router_icon_type(self):
        client = FakeDeviceClient({"ROUTER_URL":"http://127.0.0.1", "ROUTER_USERNAME":"admin", "ROUTER_PASSWORD":"test", "ROUTER_WAN_NAME":"FTTH-Data"})
        devices = client.connected_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["mac"], "00:00:5E:00:53:05")
        self.assertEqual(devices[0]["device_type"], "portátil")
        self.assertEqual(devices[0]["network"], "LAN")

    def test_local_overrides_assign_household_names_and_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            overrides = Path(tmp) / "device-overrides.csv"
            overrides.write_text("mac,name,device_type\n00:00:5E:00:53:05,dispositivo-5,luz\n", encoding="utf-8")
            previous = exporter.DEVICE_OVERRIDES_FILE
            exporter.DEVICE_OVERRIDES_FILE = overrides
            try:
                devices = [{"mac":"00:00:5E:00:53:05", "name":"unknown", "device_type":"desconocido"}]
                result = exporter.apply_device_overrides(devices)
            finally:
                exporter.DEVICE_OVERRIDES_FILE = previous
        self.assertEqual(result[0]["name"], "dispositivo-5")
        self.assertEqual(result[0]["device_type"], "luz")

    def test_renders_prometheus_metrics_without_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "router.env"
            config.write_text(
                "ROUTER_URL=http://192.0.2.1\n"
                "ROUTER_USERNAME=admin\n"
                "ROUTER_PASSWORD=private-test-value\n"
                "ROUTER_WAN_NAME=FTTH-Data\n",
                encoding="utf-8",
            )
            exporter.CONFIG_FILE = config
            with patch.object(exporter, "ZTEClient", FakeRouterClient):
                metrics = exporter.render_metrics()
        self.assertIn("router_exporter_configured 1", metrics)
        self.assertIn("router_exporter_scrape_success 1", metrics)
        self.assertIn('router_wan_received_bytes_total{connection="FTTH-Data"} 2658778925', metrics)
        self.assertIn('router_wan_transmitted_bytes_total{connection="FTTH-Data"} 1614684887', metrics)
        self.assertIn('router_connected_devices{network="LAN"} 1', metrics)
        self.assertIn('router_connected_device_info{mac="00:00:5E:00:53:05",ip="192.0.2.42",name="dispositivo-13",device_type="portátil",network="LAN",port="LAN1",ssid=""} 1', metrics)
        self.assertNotIn("private-test-value", metrics)


if __name__ == "__main__":
    unittest.main()
