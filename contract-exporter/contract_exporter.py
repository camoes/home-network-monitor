#!/usr/bin/env python3
"""Expose ISP plan speeds as Prometheus gauges for dashboard comparisons."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import os


def read_speed(name: str) -> float:
    raw = os.environ.get(name, "0").strip()
    try:
        value = float(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a non-negative number in Mbps; got {raw!r}") from exc
    if value < 0:
        raise SystemExit(f"{name} must be non-negative; got {raw!r}")
    return value * 1_000_000


DOWNLOAD_BPS = read_speed("ISP_DOWNLOAD_MBPS")
UPLOAD_BPS = read_speed("ISP_UPLOAD_MBPS")
CONFIGURED = 1 if DOWNLOAD_BPS > 0 and UPLOAD_BPS > 0 else 0

METRICS = f"""# HELP isp_contract_download_bits_per_second Contracted ISP download rate in bit/s.
# TYPE isp_contract_download_bits_per_second gauge
isp_contract_download_bits_per_second {DOWNLOAD_BPS:g}
# HELP isp_contract_upload_bits_per_second Contracted ISP upload rate in bit/s.
# TYPE isp_contract_upload_bits_per_second gauge
isp_contract_upload_bits_per_second {UPLOAD_BPS:g}
# HELP isp_contract_configured 1 when both contracted speeds are configured, otherwise 0.
# TYPE isp_contract_configured gauge
isp_contract_configured {CONFIGURED}
"""


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path not in ("/metrics", "/"):
            self.send_error(404)
            return
        body = METRICS.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    print("Contract metrics exporter listening on :9799", flush=True)
    HTTPServer(("0.0.0.0", 9799), MetricsHandler).serve_forever()
