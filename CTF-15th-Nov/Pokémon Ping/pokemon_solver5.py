#!/usr/bin/env python3
import socket
import time

def interactive_connect(host, port):
    """Connect and try multiple commands in same session"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        
        print(f"[+] Connecting to {host}:{port}...")
        s.connect((host, port))
        print("[+] Connected!")
        
        # Try to receive initial banner if any
        time.sleep(0.5)
        try:
            initial = s.recv(4096)
            if initial:
                print("[+] Initial response:")
                print(initial.decode('utf-8', errors='ignore'))
        except:
            pass
        
        # Commands to try
        commands = [
            "Blaziken",
            "blaziken",
            "BLAZIKEN",
            "echo Blaziken",
            "GET /flag",
            "flag",
            "help",
            "GET /flag HTTP/1.1\r\nHost: 0.cloud.chals.io\r\nX-Pokemon: Blaziken\r\n\r\n",
        ]
        
        for cmd in commands:
            print(f"\n[*] Sending: {repr(cmd)}")
            s.sendall((cmd + "\n").encode())
            time.sleep(0.5)
            
            try:
                response = s.recv(4096).decode('utf-8', errors='ignore')
                if response:
                    print(f"[+] Response:\n{response}")
                    if "inctf{" in response.lower() or "flag{" in response.lower():
                        print("\n" + "=" * 70)
                        print("[!!!] FLAG FOUND!")
                        print("=" * 70)
                        s.close()
                        return
            except socket.timeout:
                print("[-] No response")
        
        s.close()
        
    except Exception as e:
        print(f"[-] Error: {e}")

def simple_send(host, port, data):
    """Simple send - just connect, send data, get response"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        
        print(f"[+] Connecting and sending: {repr(data)}")
        s.connect((host, port))
        s.sendall(data.encode())
        
        time.sleep(1)
        response = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
        except:
            pass
        
        s.close()
        return response.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

HOST = "0.cloud.chals.io"
PORT = 23839

print("=" * 70)
print("Pokémon PING - Interactive Session Attempt")
print("=" * 70)

# Try interactive connection
print("\n[METHOD 1] Interactive connection with multiple commands:")
interactive_connect(HOST, PORT)

# Try simple single commands
print("\n\n[METHOD 2] Simple command attempts:")
simple_commands = [
    "Blaziken\n",
    "echo Blaziken\n",
    "blaziken\n",
]

for cmd in simple_commands:
    print(f"\n[*] Trying: {repr(cmd)}")
    resp = simple_send(HOST, PORT, cmd)
    if resp:
        print(f"Response: {resp[:200]}...")
        if "inctf{" in resp.lower() or "flag{" in resp.lower():
            print("\n[!!!] FLAG FOUND!")
            print(resp)
            break

print("\n\n[METHOD 3] You can also manually try:")
print("nc 0.cloud.chals.io 23839")
print("Then type: Blaziken")
print("Or: echo Blaziken")