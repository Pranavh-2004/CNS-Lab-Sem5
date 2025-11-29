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

# LUCARIO is the key Pokemon!
requests = [
    # PING method with Lucario
    ("PING /flag with Lucario", "PING /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\nX-Pokemon: Lucario\r\n\r\n"),
    ("PING / with Lucario", "PING / HTTP/1.1\r\nHost: 0.cloud.chals.io\r\nX-Pokemon: Lucario\r\n\r\n"),
    ("PING /lucario", "PING /lucario HTTP/1.1\r\nHost: 0.cloud.chals.io\r\n\r\n"),
    
    # GET method with Lucario
    ("GET /flag with Lucario", "GET /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\nX-Pokemon: Lucario\r\n\r\n"),
    ("GET /lucario", "GET /lucario HTTP/1.1\r\nHost: 0.cloud.chals.io\r\n\r\n"),
    ("GET /flag User-Agent Lucario", "GET /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\nUser-Agent: Lucario\r\n\r\n"),
    
    # Combination headers
    ("PING with Lucario + Ash", "PING /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\nX-Pokemon: Lucario\r\nX-Trainer: Ash\r\n\r\n"),
    ("GET with Lucario + Ash", "GET /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\nX-Pokemon: Lucario\r\nX-Trainer: Ash\r\n\r\n"),
    
    # Authorization with Lucario
    ("Authorization: Lucario", "GET /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\nAuthorization: Lucario\r\n\r\n"),
    ("PING Authorization: Lucario", "PING /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\nAuthorization: Lucario\r\n\r\n"),
]

print("=" * 70)
print("Pokémon PING CTF Solver - LUCARIO Edition")
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
        # Check if response is different
        elif "Unauthorized" not in response or len(response) < 1000:
            print("[+] Different response:")
            print(response)
        else:
            print("[-] Still unauthorized")
    else:
        print("[-] No response")

print("\n[*] Scan complete!")