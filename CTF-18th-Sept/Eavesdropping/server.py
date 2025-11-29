#!/usr/bin/env python3
# Usage: python3 server.py --target https://??? --delay 0.5 --port 8080

import urllib.request
import argparse
import time
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import requests

# default order
ORDER = [2, 0, 5, 7, 1, 9, 3, 4, 6, 8]

# create unverified SSL context
ssl_context = ssl._create_unverified_context()

# store fragments after fetching
fragments = {}

# Custom HTTP handler that suppresses logging
class SilentHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return  # suppress console logs

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")  # minimal response

def run_server(port):
    server = HTTPServer(("0.0.0.0", port), SilentHandler)
    server.serve_forever()

def fetch_fragment(base_url, idx, timeout=5):
    url = f"{base_url.rstrip('/')}/fragment?order={idx}"
    req = urllib.request.Request(url, method='GET', headers={
        'User-Agent': 'emitter/auto'
    })
    with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as resp:
        return resp.read().decode('utf-8', errors='replace')

def replay_fragment(idx, data, port):
    """POST fragment locally so students must inspect packets"""
    url = f"http://127.0.0.1:{port}/"
    try:
        #requests.post(url, data=f"{idx}.{data}".encode('utf-8'))
        requests.post(url, data=f"{idx}.{data}".encode('utf-8'), headers={'Content-Type':'text/plain; charset=utf-8'})

    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="HTTPS fragment server base URL")
    parser.add_argument("--delay", type=float, default=0.5, help="seconds between requests")
    parser.add_argument("--order", nargs="*", type=int, default=None, help="override order")
    parser.add_argument("--port", type=int, default=8080, help="local HTTP port for capture")
    args = parser.parse_args()

    order = ORDER if args.order is None else args.order

    # start local HTTP server in a thread
    t = threading.Thread(target=run_server, args=(args.port,), daemon=True)
    t.start()

    for idx in order:
        try:
            frag = fetch_fragment(args.target, idx)
            fragments[f"{idx}.{frag}"] = frag
            # immediately replay as POST for Wireshark capture
            replay_fragment(idx, frag, args.port)
            time.sleep(args.delay)
        except Exception as e:
            print(f"[error] failed to fetch fragment {idx}: {e}")

    print("Did hear that?")

    # keep server alive for late joins
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[server] stopped.")

if __name__ == "__main__":
    main()

