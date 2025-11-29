#!/usr/bin/env python3
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import base64
import time

# final order array
ORDER = [2, 0, 5, 7, 1, 9, 3, 4, 6, 8]

# store received fragments
fragments = {}

class CaptureHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return  # suppress logs

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode()
        # expected format: idx.fragment
        try:
            idx_str, frag = body.split('.', 1)
            idx = int(idx_str)
            fragments[idx] = frag
            print(f"[+] Captured fragment {idx}: {frag}")
        except Exception as e:
            print(f"[!] Failed to parse fragment: {body} ({e})")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

def run_server(port=8080):
    server = HTTPServer(('0.0.0.0', port), CaptureHandler)
    print(f"[server] Listening on port {port}...")
    server.serve_forever()

def reconstruct_and_decode():
    while True:
        if len(fragments) >= 10:
            # reconstruct in ORDER
            combined = ''.join(fragments[i] for i in ORDER)
            print(f"\n[+] Combined Base64 string:\n{combined}\n")
            try:
                decoded = base64.b64decode(combined)
                print(f"[+] Decoded result:\n{decoded.decode(errors='replace')}")
            except Exception as e:
                print(f"[!] Failed to decode: {e}")
            break
        time.sleep(0.5)

if __name__ == "__main__":
    threading.Thread(target=run_server, daemon=True).start()
    reconstruct_and_decode()