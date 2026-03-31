from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from detect_public import run_scan, run_auto_scan

class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        descriptor = params.get("descriptor", [None])[0]

        if not descriptor:
            self._json(400, {"error": "Missing required query parameter: descriptor"})
            return

        try:
            offset = int(params.get("offset", ["0"])[0])
        except (ValueError, TypeError):
            offset = 0

        try:
            count = int(params.get("count", ["60"])[0])
        except (ValueError, TypeError):
            count = 60

        branch_mode = params.get("branch", ["receive"])[0]
        if branch_mode not in ("receive", "change", "both"):
            branch_mode = "receive"

        auto = params.get("auto", ["0"])[0] in ("1", "true", "yes")

        try:
            if auto:
                report = run_auto_scan(descriptor, branch_mode=branch_mode)
            else:
                report = run_scan(descriptor, offset=offset, count=count, branch_mode=branch_mode)
            self._json(200, report)
        except ValueError as e:
            self._json(400, {"error": str(e)})
        except Exception as e:
            self._json(500, {"error": "Internal server error", "detail": str(e)})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)
