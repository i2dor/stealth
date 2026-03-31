from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from detect_public import run_scan

class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        descriptor = params.get("descriptor", [None])[0]

        if not descriptor:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            body = json.dumps({"error": "Missing required query parameter: descriptor"})
            self.wfile.write(body.encode())
            return

        try:
            offset = int(params.get("offset", ["0"])[0])
        except (ValueError, TypeError):
            offset = 0

        try:
            count = int(params.get("count", ["60"])[0])
        except (ValueError, TypeError):
            count = 60

        try:
            report = run_scan(descriptor, offset=offset, count=count)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(report).encode())
        except ValueError as e:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            body = json.dumps({"error": str(e)})
            self.wfile.write(body.encode())
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            body = json.dumps({"error": "Internal server error", "detail": str(e)})
            self.wfile.write(body.encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
