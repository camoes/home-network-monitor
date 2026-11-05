"""Tests for the packet-capture parser and metric rendering (no capture needed)."""

import ipaddress
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

import sensor


LINE_SNI = "1726660000.123\t192.0.2.10\t93.184.216.34\t\t\t53614\t443\t\t\t1200\t\twww.example.com\t"
LINE_DNS = "1726660001.500\t192.0.2.10\t8.8.8.8\t\t\t53615\t\t53615\t53\t80\texample.com\t\t"
LINE_EMPTY = "1726660002.000\t192.0.2.10\t1.1.1.1\t\t\t53616\t443\t\t\t1400\t\t\t"
LINE_BAD = "not\ta\tpacket"
# ip.proto = 17 (UDP) en el puerto 443: HTTP/3 sobre QUIC.
LINE_QUIC = ("1726660020.000\t192.0.2.10\t142.250.184.78\t\t\t\t\t61000\t443\t1350\t\t\t\t17\t")


def dns_line(query: str, src: str = "192.0.2.10", dst: str = "8.8.8.8") -> str:
    return f"1726660003.000\t{src}\t{dst}\t\t\t53617\t\t53617\t53\t80\t{query}\t\t"


class ParserTests(unittest.TestCase):
    def test_tls_sni_flow(self):
        flow = sensor.parse_line(LINE_SNI) or {}
        self.assertEqual(flow["domain"], "www.example.com")
        self.assertEqual(flow["dport"], "443")
        self.assertEqual(sensor.service(flow["dport"]), "https")
        self.assertEqual(flow["bytes"], 1200)
        self.assertTrue(flow["sni"])

    def test_dns_flow(self):
        flow = sensor.parse_line(LINE_DNS) or {}
        self.assertEqual(flow["domain"], "example.com")
        self.assertEqual(flow["dport"], "53")
        self.assertEqual(sensor.service(flow["dport"]), "dns")
        self.assertTrue(flow["dns"])

    def test_flow_without_name_still_counts(self):
        flow = sensor.parse_line(LINE_EMPTY) or {}
        self.assertEqual(flow["domain"], "")
        self.assertEqual(flow["bytes"], 1400)

    def test_malformed_line_is_ignored(self):
        self.assertIsNone(sensor.parse_line(LINE_BAD))

    def test_udp_443_is_quic(self):
        flow = sensor.parse_line(LINE_QUIC) or {}
        self.assertEqual(flow["ipproto"], "17")
        self.assertEqual(flow["transport"], "udp")
        self.assertEqual(sensor.service(flow["dport"], flow["transport"]), "quic")

    def test_transport_falls_back_to_the_ports(self):
        flow = sensor.parse_line(LINE_SNI) or {}
        self.assertEqual(flow["ipproto"], "")
        self.assertEqual(flow["transport"], "tcp")
        self.assertEqual(sensor.service(flow["dport"], flow["transport"]), "https")

    def test_private_destinations_are_not_geolocated(self):
        self.assertTrue(sensor.is_private("192.0.2.5"))
        self.assertTrue(sensor.is_private("127.0.0.1"))
        self.assertFalse(sensor.is_private("8.8.8.8"))


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        sensor.STATE_DIR = Path(self.tmp.name)
        sensor.GEO_CACHE = Path(self.tmp.name) / "geo.json"
        sensor.PEERS_CACHE = Path(self.tmp.name) / "peers.json"
        sensor._FLOWS.clear()
        sensor._CLIENTS.clear()
        sensor._DOMAINS.clear()
        sensor._DSTS.clear()
        sensor._PEER_DOMAIN.clear()
        sensor._PEER_SEEN.clear()
        sensor._PEERS_DIRTY = False
        sensor._COUNTERS.update({"packets": 0, "bytes": 0, "dns": 0, "sni": 0, "blocks": 0})
        sensor._LOCAL_IPS = {"192.0.2.10"}
        sensor._STATUS["tshark"] = "running"

    def tearDown(self):
        self.tmp.cleanup()

    def test_records_flow_and_renders_metrics(self):
        for line in (LINE_SNI, LINE_DNS, LINE_EMPTY):
            sensor.record(sensor.parse_line(line) or {})
        text = sensor.render()
        self.assertIn('netviz_flow_bytes_total{dst="93.184.216.34",domain="www.example.com",proto="https/out"} 1200', text)
        self.assertIn('netviz_domain_bytes_total{domain="example.com"} 80', text)
        self.assertIn("netviz_capture_packets_total 3", text)
        self.assertIn("netviz_capture_up 1", text)

    def test_private_destination_has_no_coordinates(self):
        sensor.record(sensor.parse_line(LINE_DNS.replace("8.8.8.8", "192.0.2.1")) or {})
        text = sensor.render()
        self.assertIn('dst="192.0.2.1",city=""', text)

    def test_quic_flow_is_labelled_quic(self):
        sensor.record(sensor.parse_line(LINE_QUIC) or {})
        text = sensor.render()
        self.assertIn('dst="142.250.184.78",domain="",proto="quic/out"', text)


class MirrorModeTests(unittest.TestCase):
    """En un puerto espejo la dirección se decide por el rango de la LAN."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        sensor.STATE_DIR = Path(self.tmp.name)
        sensor.GEO_CACHE = Path(self.tmp.name) / "geo.json"
        sensor.PEERS_CACHE = Path(self.tmp.name) / "peers.json"
        sensor._FLOWS.clear()
        sensor._CLIENTS.clear()
        sensor._DOMAINS.clear()
        sensor._DSTS.clear()
        sensor._PEER_DOMAIN.clear()
        sensor._PEER_SEEN.clear()
        sensor._PEERS_DIRTY = False
        sensor._COUNTERS.update({"packets": 0, "bytes": 0, "dns": 0, "sni": 0, "blocks": 0})
        sensor._LOCAL_IPS = {"192.0.2.46"}      # IP del PC que captura
        sensor.LAN_NETS = [ipaddress.ip_network("192.0.2.0/24"),
                           ipaddress.ip_network("198.51.100.0/24")]
        sensor._STATUS["tshark"] = "running"

    def tearDown(self):
        sensor.LAN_NETS = []
        self.tmp.cleanup()

    def test_lan_to_wan_is_outbound_with_public_peer(self):
        # 192.0.2.64 (tele) -> 93.184.216.34, aunque la IP del PC sea otra
        flow = sensor.parse_line(LINE_SNI.replace("192.0.2.10", "192.0.2.64")) or {}
        sensor.record(flow)
        text = sensor.render()
        self.assertIn('dst="93.184.216.34",domain="www.example.com",proto="https/out"', text)

    def test_wan_to_lan_is_inbound(self):
        line = "1726660003.000	93.184.216.34	192.0.2.64			443	61000			900			"
        sensor.record(sensor.parse_line(line) or {})
        text = sensor.render()
        self.assertIn('dst="93.184.216.34"', text)
        self.assertIn("https/in", text)

    def test_client_is_attributed_with_name_and_type(self):
        sensor._NAMES = {"192.0.2.64": {"name": "dispositivo-8", "type": "television"}}
        flow = sensor.parse_line(LINE_SNI.replace("192.0.2.10", "192.0.2.64")) or {}
        sensor.record(flow)
        text = sensor.render()
        self.assertIn('client="192.0.2.64",name="dispositivo-8",type="television"', text)
        self.assertIn('dst="93.184.216.34"', text)

    def test_second_lan_range_is_attributed(self):
        # 198.51.100.0/24 (lavavajillas, aire) también es LAN del router
        sensor._NAMES = {"198.51.100.6": {"name": "dispositivo-11", "type": "electrodoméstico"}}
        line = ("1726660005.000\t198.51.100.6\t51.140.0.1\t\t\t52000\t443\t\t\t"
                "1000\t\tiot.bosch.com\t")
        sensor.record(sensor.parse_line(line) or {})
        text = sensor.render()
        self.assertIn('client="198.51.100.6",name="dispositivo-11"', text)
        self.assertIn('domain="iot.bosch.com"', text)

    def test_lan_to_lan_is_ignored(self):
        line = "1726660004.000	192.0.2.64	192.0.2.20			50000	8009			700			"
        sensor.record(sensor.parse_line(line) or {})
        self.assertEqual(sensor._FLOWS, {})


class CdnFallbackTests(unittest.TestCase):
    """Tabla IP->etiqueta: sólo respaldo cuando el flujo no tiene dominio."""

    TABLE = {
        "enabled": True,
        "prefixes": {
            "212.166.128.0/18": "streaming vídeo – CDN Vodafone España (AS12430)",
            "8.8.8.0/24": "DNS público Google (ficticio, para probar)",
        },
    }

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "cdn-map.json"
        sensor.STATE_DIR = Path(self.tmp.name)
        sensor.GEO_CACHE = Path(self.tmp.name) / "geo.json"
        sensor.PEERS_CACHE = Path(self.tmp.name) / "peers.json"
        sensor._FLOWS.clear()
        sensor._CLIENTS.clear()
        sensor._DOMAINS.clear()
        sensor._DSTS.clear()
        sensor._PEER_DOMAIN.clear()
        sensor._PEER_SEEN.clear()
        sensor._PEERS_DIRTY = False
        sensor._CDN_BYTES.clear()
        sensor._CDN_SEEN.clear()
        sensor._COUNTERS.update({"packets": 0, "bytes": 0, "dns": 0, "sni": 0, "cdn": 0})
        sensor._LOCAL_IPS = {"192.0.2.46"}
        sensor.LAN_NETS = [ipaddress.ip_network("192.0.2.0/24")]
        sensor._NAMES = {"192.0.2.64": {"name": "dispositivo-10",
                                         "type": "televisión"}}
        sensor._STATUS["tshark"] = "running"

    def tearDown(self):
        sensor.LAN_NETS = []
        sensor._NAMES = {}
        sensor.CDN_DEBUG = False
        sensor.load_cdn("")          # deja el respaldo apagado para el resto de tests
        self.tmp.cleanup()

    def write_table(self, table) -> None:
        self.path.write_text(json.dumps(table, ensure_ascii=False), encoding="utf-8")
        sensor.load_cdn(self.path)

    def inbound_video_line(self) -> str:
        # 212.166.133.207 -> tele, sin SNI/DNS/Host (QUIC o conexión establecida)
        return "1726660010.000\t212.166.133.207\t192.0.2.64\t\t\t443\t61000\t\t\t9000000\t\t\t"

    def test_labels_domainless_flow_and_keeps_client_counter(self):
        self.write_table(self.TABLE)
        sensor.record(sensor.parse_line(self.inbound_video_line()) or {})
        text = sensor.render()
        self.assertIn('client="192.0.2.64",name="dispositivo-10",type="televisión"', text)
        self.assertIn('dst="212.166.133.207",domain="",proto="https/in",'
                      'cdn="streaming vídeo – CDN Vodafone España (AS12430)"', text)
        self.assertIn('netviz_cdn_named_bytes_total{cdn="streaming vídeo – CDN Vodafone España '
                      '(AS12430)"} 9000000', text)
        self.assertEqual(sensor._COUNTERS["cdn"], 1)

    def test_observed_domain_wins_over_table(self):
        self.write_table(self.TABLE)
        line = self.inbound_video_line().replace("9000000\t\t\t", "9000000\t\tvodafone.es\t")
        sensor.record(sensor.parse_line(line) or {})
        text = sensor.render()
        series = [ln for ln in text.splitlines()
                  if ln.startswith("netviz_client_bytes_total") and "212.166.133.207" in ln]
        self.assertTrue(series)
        for ln in series:
            self.assertIn('domain="vodafone.es"', ln)
            self.assertNotIn("cdn=", ln)
        self.assertEqual(sensor._COUNTERS["cdn"], 0)

    def test_longest_prefix_wins(self):
        self.write_table({"prefixes": {"212.166.128.0/18": "genérica",
                                       "212.166.133.0/24": "específica"}})
        self.assertEqual(sensor.cdn_label("212.166.133.207"), "específica")
        self.assertEqual(sensor.cdn_label("212.166.140.10"), "genérica")

    def test_unknown_and_invalid_destinations_are_untouched(self):
        self.write_table(self.TABLE)
        self.assertEqual(sensor.cdn_label("1.1.1.1"), "")
        self.assertEqual(sensor.cdn_label("no-es-una-ip"), "")

    def test_table_can_be_switched_off(self):
        self.write_table({"enabled": False,
                          "prefixes": {"212.166.128.0/18": "no debería salir"}})
        self.assertFalse(sensor._CDN_ENABLED)
        sensor.record(sensor.parse_line(self.inbound_video_line()) or {})
        text = sensor.render()
        self.assertNotIn("cdn=", text)
        self.assertFalse([ln for ln in text.splitlines()
                          if ln.startswith("netviz_cdn_named_bytes_total{")])

    def test_hot_reload_picks_up_file_changes(self):
        self.write_table({"prefixes": {"212.166.0.0/16": "antes"}})
        self.assertEqual(sensor.cdn_label("212.166.133.207"), "antes")
        self.path.write_text(json.dumps({"prefixes": {"212.166.133.0/24": "después"}}),
                             encoding="utf-8")
        os.utime(self.path, (time.time() + 5, time.time() + 5))
        self.assertEqual(sensor.refresh_cdn(), 1)
        self.assertEqual(sensor.cdn_label("212.166.133.207"), "después")

    def test_table_can_enable_debug_logging(self):
        self.write_table({"debug": True, "prefixes": {"212.166.128.0/18": "x"}})
        self.assertTrue(sensor.CDN_DEBUG)
        sensor.record(sensor.parse_line(self.inbound_video_line()) or {})
        # una sola línea de debug por destino, no una por paquete
        sensor.record(sensor.parse_line(self.inbound_video_line()) or {})
        self.assertEqual(sensor._CDN_SEEN, {"212.166.133.207"})

    def test_missing_table_is_the_previous_behaviour(self):
        sensor.load_cdn(Path(self.tmp.name) / "no-existe.json")
        self.assertFalse(sensor._CDN_ENABLED)
        sensor.record(sensor.parse_line(self.inbound_video_line()) or {})
        text = sensor.render()
        self.assertIn('dst="212.166.133.207",domain="",proto="https/in"', text)
        self.assertNotIn("cdn=", text)


class PeerPersistenceTests(unittest.TestCase):
    """IP->dominio: sobrevive al reinicio, caduca y no se aprende de consultas DNS."""

    TV = "192.0.2.64"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        sensor.STATE_DIR = Path(self.tmp.name)
        sensor.GEO_CACHE = Path(self.tmp.name) / "geo.json"
        sensor.PEERS_CACHE = Path(self.tmp.name) / "peers.json"
        self.ttl = sensor.PEERS_TTL
        sensor.PEERS_TTL = 36 * 3600
        sensor._FLOWS.clear()
        sensor._CLIENTS.clear()
        sensor._DOMAINS.clear()
        sensor._DSTS.clear()
        sensor._PEER_DOMAIN.clear()
        sensor._PEER_SEEN.clear()
        sensor._PEERS_DIRTY = False
        sensor._COUNTERS.update({"packets": 0, "bytes": 0, "dns": 0, "sni": 0, "cdn": 0})
        sensor._LOCAL_IPS = {"192.0.2.46"}
        sensor.LAN_NETS = [ipaddress.ip_network("192.0.2.0/24")]
        sensor._NAMES = {self.TV: {"name": "dispositivo-9", "type": "televisión"}}
        sensor._STATUS["tshark"] = "running"
        sensor.load_cdn("")            # el respaldo por tabla no interviene aquí

    def tearDown(self):
        sensor.PEERS_TTL = self.ttl
        sensor.LAN_NETS = []
        sensor._NAMES = {}
        self.tmp.cleanup()

    # -- utilidades
    def sni_line(self, peer: str = "142.251.151.4", name: str = "www.youtube.com") -> str:
        return (f"1726660030.000\t{self.TV}\t{peer}\t\t\t50000\t443\t\t\t1200\t\t{name}\t")

    def inbound_line(self, peer: str = "142.251.151.4") -> str:
        return f"1726660031.000\t{peer}\t{self.TV}\t\t\t443\t61000\t\t\t900000\t\t\t"

    def restart(self) -> int:
        """Simula un reinicio: se pierde la memoria y el sensor relee el disco."""
        sensor._PEER_DOMAIN.clear()
        sensor._PEER_SEEN.clear()
        return sensor.load_peers()

    def write_peers(self, peers: dict) -> None:
        sensor.PEERS_CACHE.write_text(json.dumps({"version": 1, "peers": peers}),
                                      encoding="utf-8")

    # -- persistencia
    def test_learned_domain_survives_restart(self):
        sensor.record(sensor.parse_line(self.sni_line()) or {})
        self.assertEqual(sensor._PEER_DOMAIN.get("142.251.151.4"), "www.youtube.com")
        self.assertTrue(sensor.save_peers())
        self.assertTrue(sensor.PEERS_CACHE.exists())
        self.assertEqual(self.restart(), 1)
        # sin ningún ClientHello nuevo, el tráfico ya está atribuido
        sensor.record(sensor.parse_line(self.inbound_line()) or {})
        text = sensor.render()
        self.assertIn('client="192.0.2.64",name="dispositivo-9",type="televisión",'
                      'dst="142.251.151.4",domain="www.youtube.com",proto="https/in"', text)

    def test_nothing_is_written_without_changes(self):
        self.assertFalse(sensor.save_peers())          # sin cambios no se toca el disco
        self.assertFalse(sensor.PEERS_CACHE.exists())

    def test_expired_entry_is_dropped_on_load(self):
        now = time.time()
        self.write_peers({"1.1.1.1": {"domain": "viejo.example", "ts": now - 40 * 3600},
                          "2.2.2.2": {"domain": "reciente.example", "ts": now - 3600}})
        self.assertEqual(sensor.load_peers(), 1)
        self.assertEqual(sensor._PEER_DOMAIN, {"2.2.2.2": "reciente.example"})

    def test_prune_drops_stale_entries_at_runtime(self):
        sensor.learn_peer("3.3.3.3", "caducado.example", when=time.time() - 37 * 3600)
        sensor.learn_peer("4.4.4.4", "fresco.example")
        self.assertEqual(sensor.prune_peers(), 1)
        self.assertEqual(sensor._PEER_DOMAIN, {"4.4.4.4": "fresco.example"})

    def test_broken_state_file_is_not_fatal(self):
        sensor.PEERS_CACHE.write_text("{esto no es json", encoding="utf-8")
        self.assertEqual(sensor.load_peers(), 0)
        self.assertEqual(sensor._PEER_DOMAIN, {})

    def test_junk_entries_are_ignored(self):
        now = time.time()
        self.write_peers({"no-es-una-ip": {"domain": "x.example", "ts": now},
                          "4.4.4.4": "",
                          "5.5.5.5": {"domain": "ok.example"}})   # sin ts: cuenta desde ahora
        self.assertEqual(sensor.load_peers(), 1)
        self.assertEqual(sensor._PEER_DOMAIN, {"5.5.5.5": "ok.example"})

    # -- aislamiento de las consultas DNS
    def test_dns_query_does_not_name_the_dns_server(self):
        sensor.record(sensor.parse_line(dns_line("nrdp.logs.netflix.com", src=self.TV)) or {})
        self.assertNotIn("8.8.8.8", sensor._PEER_DOMAIN)
        text = sensor.render()
        # el flujo DNS es del servidor DNS, no del dominio consultado
        self.assertIn('netviz_flow_bytes_total{dst="8.8.8.8",domain="",proto="dns/out"} 80', text)
        self.assertNotIn('dst="8.8.8.8",domain="nrdp.logs.netflix.com"', text)
        # y el tráfico posterior hacia ese servidor tampoco hereda el nombre
        sensor.record(sensor.parse_line(self.inbound_line("8.8.8.8")) or {})
        text = sensor.render()
        self.assertIn('dst="8.8.8.8",domain="",proto="https/in"', text)
        self.assertNotIn('dst="8.8.8.8",domain="nrdp.logs.netflix.com"', text)

    def test_dns_query_is_not_named_by_the_cdn_table(self):
        table = Path(self.tmp.name) / "cdn-map.json"
        table.write_text(json.dumps({"prefixes": {"8.8.8.0/24": "DNS público"}}), encoding="utf-8")
        sensor.load_cdn(table)
        self.assertTrue(sensor._CDN_ENABLED)
        sensor.record(sensor.parse_line(dns_line("example.com", src=self.TV)) or {})
        self.assertNotIn("cdn=", sensor.render())

    def test_contaminated_entry_is_forgotten(self):
        sensor.learn_peer("8.8.8.8", "nrdp.logs.netflix.com")     # como lo dejaba la versión anterior
        self.assertIn("8.8.8.8", sensor._PEER_DOMAIN)
        sensor.record(sensor.parse_line(dns_line("nrdp.logs.netflix.com", src=self.TV)) or {})
        self.assertNotIn("8.8.8.8", sensor._PEER_DOMAIN)

    def test_dns_packets_still_count_as_domains(self):
        sensor.record(sensor.parse_line(dns_line("example.com", src=self.TV)) or {})
        text = sensor.render()
        self.assertIn('netviz_domain_bytes_total{domain="example.com"} 80', text)
        self.assertEqual(sensor._COUNTERS["dns"], 1)


if __name__ == "__main__":
    unittest.main()
