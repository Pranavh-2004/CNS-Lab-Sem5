#!/usr/bin/env python3
"""
Decrypt HTTPS traffic from pcap using RSA private key
"""

import subprocess
import json
import hashlib
import hmac
from scapy.all import rdpcap, TCP, Raw, IP
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sys

# Load the pcap file
print("[*] Loading pcap file...")
packets = rdpcap("challenge5.pcap")

# Extract RSA private key
print("[*] Loading RSA private key...")
with open("server.key", "rb") as f:
    key_data = f.read()
    private_key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())

print("[*] Key loaded successfully")
print(f"[*] Key type: {type(private_key)}")

# Extract all TLS packets
print("[*] Extracting TLS handshake information...")
tls_packets = []
for pkt in packets:
    if TCP in pkt and (pkt[TCP].sport == 4443 or pkt[TCP].dport == 4443):
        if Raw in pkt:
            tls_packets.append(pkt)

print(f"[*] Found {len(tls_packets)} TLS packets")

# Try to parse TLS records manually
print("\n[*] Analyzing TLS records...")
for i, pkt in enumerate(tls_packets[:20]):
    payload = bytes(pkt[Raw].load)
    record_type = payload[0]
    version = (payload[1] << 8) | payload[2]
    length = (payload[3] << 8) | payload[4]
    
    type_names = {
        0x16: "Handshake",
        0x17: "Application Data",
        0x14: "Change Cipher Spec",
        0x15: "Alert",
        0x18: "Heartbeat"
    }
    
    type_name = type_names.get(record_type, f"Unknown(0x{record_type:02x})")
    print(f"  Packet {i}: Type=0x{record_type:02x}({type_name}) Version=0x{version:04x} Length={length}")

# Try to extract application data
print("\n[*] Extracting encrypted application data...")
app_data_payloads = []
for pkt in tls_packets:
    payload = bytes(pkt[Raw].load)
    if payload[0] == 0x17:  # Application Data
        app_data_payloads.append(payload)

print(f"[*] Found {len(app_data_payloads)} encrypted application data records")

if app_data_payloads:
    print("\n[*] First encrypted record details:")
    first = app_data_payloads[0]
    print(f"  Hex: {first[:80].hex()}")
    print(f"  Length: {len(first)} bytes")
    print(f"  Record length field: {(first[3] << 8) | first[4]}")

# Try to use tshark with json output for more detailed parsing
print("\n[*] Attempting to use tshark for TLS analysis...")
result = subprocess.run([
    "tshark", "-r", "challenge5.pcap",
    "-Y", "tls.handshake",
    "-T", "json"
], capture_output=True, text=True)

if result.stdout:
    try:
        tls_handshakes = json.loads(result.stdout)
        print(f"[*] Found {len(tls_handshakes)} TLS handshake messages in JSON")
        if tls_handshakes:
            # Look for server key exchange or certificate messages
            for msg in tls_handshakes[:3]:
                if "_source" in msg and "layers" in msg["_source"]:
                    print(f"  - Frame: {msg.get('_index', 'N/A')}")
    except json.JSONDecodeError:
        print("[-] Could not parse JSON output")
        print(result.stdout[:500])

# Now let's try to see if we can manually reconstruct the TLS session
print("\n[*] Analyzing TLS session keys...")

# Extract Client Hello
client_hello_packets = []
for pkt in tls_packets:
    payload = bytes(pkt[Raw].load)
    if payload[0] == 0x16:  # Handshake
        hs_type = payload[5]
        if hs_type == 0x01:  # Client Hello
            client_hello_packets.append(payload)

print(f"[*] Found {len(client_hello_packets)} Client Hello messages")

print("\n[*] Attempting raw TCP stream reconstruction...")
# Reconstruct TCP streams
from collections import defaultdict

tcp_streams = defaultdict(lambda: {"client_to_server": b"", "server_to_client": b""})

for pkt in tls_packets:
    if TCP in pkt and Raw in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        
        stream_id = f"{src}:{sport}-{dst}:{dport}"
        payload = bytes(pkt[Raw].load)
        
        if dport == 4443:
            tcp_streams[stream_id]["client_to_server"] += payload
        else:
            tcp_streams[stream_id]["server_to_client"] += payload

print(f"[*] Found {len(tcp_streams)} TCP streams")

for stream_id, data in list(tcp_streams.items())[:3]:
    print(f"\n  Stream: {stream_id}")
    print(f"    Client→Server: {len(data['client_to_server'])} bytes")
    print(f"    Server→Client: {len(data['server_to_client'])} bytes")

print("\n[*] Trying alternative approach with tshark follow stream...")
result = subprocess.run([
    "tshark", "-r", "challenge5.pcap",
    "-q", "-z", "follow,tcp,ascii,0"
], capture_output=True, text=True)

if result.stdout:
    print("[*] Follow stream output:")
    print(result.stdout[:1000])

print("\n[!] Standard Wireshark decryption methods not working.")
print("[!] The RSA private key is for certificate authentication, not for decrypting application data.")
print("[!] Need to extract the actual session keys from the TLS handshake.")
