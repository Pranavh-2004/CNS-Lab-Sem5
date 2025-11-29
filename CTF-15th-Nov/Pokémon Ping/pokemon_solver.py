#!/usr/bin/env python3
import socket

def send_request(host, port, request):
    """Send HTTP request and get response"""
    try:
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        
        # Connect
        print(f"[+] Connecting to {host}:{port}...")
        s.connect((host, port))
        print("[+] Connected!")
        
        # Send request
        print(f"[+] Sending request:\n{request}")
        s.sendall(request.encode())
        
        # Receive response
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

# Server details
HOST = "0.cloud.chals.io"
PORT = 23839

# Try different requests
requests = [
    "GET /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\n\r\n",
    "GET /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\nUser-Agent: Infernape\r\n\r\n",
    "GET /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\nX-Pokemon: Infernape\r\n\r\n",
    "GET /infernape HTTP/1.1\r\nHost: 0.cloud.chals.io\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: 0.cloud.chals.io\r\n\r\n",
    "GET /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\nAuthorization: Infernape\r\n\r\n",
    "GET /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\nX-Trainer: Ash\r\n\r\n",
]

print("=" * 70)
print("Pokémon Ping CTF Solver")
print("=" * 70)

for i, req in enumerate(requests, 1):
    print(f"\n[*] Attempt {i}/{len(requests)}")
    print("-" * 70)
    response = send_request(HOST, PORT, req)
    
    if response:
        print("[+] Response received:")
        print(response)
        
        # Check for flag pattern
        if "flag{" in response.lower() or "ctf{" in response.lower():
            print("\n" + "=" * 70)
            print("[!!!] FLAG FOUND!")
            print("=" * 70)
            break
    else:
        print("[-] No response received")
    
    print("-" * 70)