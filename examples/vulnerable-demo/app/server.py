"""Minimal note service. `name` and `path` come straight off the request."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from app.notes import export_note, read_note


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        if self.path.startswith("/export"):
            body = export_note(q.get("name", ["untitled"])[0])
        else:
            body = read_note(q.get("path", ["welcome.txt"])[0])
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body.encode())


def main():
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
