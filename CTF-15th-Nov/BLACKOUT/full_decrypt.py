#!/usr/bin/env python3
"""
Full TLS decryption: Parse handshake, decrypt PMS, derive session keys, decrypt application data
"""

import struct
import hashlib
import hmac
from scapy.all import rdpcap, TCP, Raw, IP
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Load the pcap
packets = rdpcap("challenge5.pcap")

# Load RSA key
with open("server.key", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(), password=None, backend=default_backend()
    )

# Helper functions
def PRF_TLS12(secret, label, seed, length):
    """TLS 1.2 PRF using SHA256"""
    import hashlib
    import hmac
    
    result = b""
    A = hmac.new(secret, label + seed, hashlib.sha256).digest()
    
    while len(result) < length:
        result += hmac.new(secret, A + label + seed, hashlib.sha256).digest()
        A = hmac.new(secret, A, hashlib.sha256).digest()
    
    return result[:length]

def parse_tls_record(data):
    """Parse a single TLS record"""
    if len(data) < 5:
        return None, 0
    
    record_type = data[0]
    version = (data[1] << 8) | data[2]
    length = (data[3] << 8) | data[4]
    content = data[5:5+length]
    total_len = 5 + length
    
    return {
        'type': record_type,
        'version': version,
        'length': length,
        'content': content
    }, total_len

# Extract all TLS payloads from all packets
tls_payloads_by_dir = {"client_to_server": [], "server_to_client": []}
for pkt in packets:
    if TCP in pkt and (pkt[TCP].sport == 4443 or pkt[TCP].dport == 4443) and Raw in pkt:
        direction = "client_to_server" if pkt[TCP].dport == 4443 else "server_to_client"
        tls_payloads_by_dir[direction].append(bytes(pkt[Raw].load))

print(f"[*] Client->Server: {len(tls_payloads_by_dir['client_to_server'])} packets")
print(f"[*] Server->Client: {len(tls_payloads_by_dir['server_to_client'])} packets")

# Parse handshake messages
handshake_data = {
    "client_hello": None,
    "server_hello": None,
    "certificate": None,
    "server_hello_done": None,
    "client_key_exchange": None,
    "pms": None,
    "client_finished": None,
    "server_finished": None
}

# Parse Client Hello
for payload in tls_payloads_by_dir["client_to_server"]:
    offset = 0
    while offset < len(payload):
        record, rec_len = parse_tls_record(payload[offset:])
        if record is None:
            break
        
        if record['type'] == 0x16:  # Handshake
            content = record['content']
            if len(content) > 4:
                hs_type = content[0]
                hs_length = (content[1] << 16) | (content[2] << 8) | content[3]
                hs_content = content[4:4+hs_length]
                
                if hs_type == 1 and handshake_data["client_hello"] is None:  # Client Hello
                    handshake_data["client_hello"] = hs_content
                    print(f"\n[+] Found Client Hello ({len(hs_content)} bytes)")
                    print(f"    First 50 bytes (hex): {hs_content[:50].hex()}")
                
                elif hs_type == 16 and handshake_data["client_key_exchange"] is None:  # Client Key Exchange
                    if len(hs_content) > 2:
                        pms_len = (hs_content[0] << 8) | hs_content[1]
                        encrypted_pms = hs_content[2:2+pms_len]
                        
                        try:
                            pms = private_key.decrypt(encrypted_pms, padding.PKCS1v15())
                            handshake_data["pms"] = pms
                            handshake_data["client_key_exchange"] = hs_content
                            print(f"\n[+] Decrypted PMS: {pms.hex()}")
                        except:
                            pass
        
        offset += rec_len

# Parse Server Hello
for payload in tls_payloads_by_dir["server_to_client"]:
    offset = 0
    while offset < len(payload):
        record, rec_len = parse_tls_record(payload[offset:])
        if record is None:
            break
        
        if record['type'] == 0x16:  # Handshake
            content = record['content']
            if len(content) > 4:
                hs_type = content[0]
                hs_length = (content[1] << 16) | (content[2] << 8) | content[3]
                hs_content = content[4:4+hs_length]
                
                if hs_type == 2 and handshake_data["server_hello"] is None:  # Server Hello
                    handshake_data["server_hello"] = hs_content
                    print(f"\n[+] Found Server Hello ({len(hs_content)} bytes)")
                    print(f"    First 50 bytes (hex): {hs_content[:50].hex()}")
                    
                    # Extract random
                    if len(hs_content) > 34:
                        server_random = hs_content[2:34]
                        print(f"    Server Random: {server_random.hex()}")
        
        offset += rec_len

# Extract Client Random from Client Hello
if handshake_data["client_hello"]:
    client_hello = handshake_data["client_hello"]
    if len(client_hello) > 34:
        client_random = client_hello[2:34]
        print(f"\n[+] Client Random: {client_random.hex()}")
else:
    print("\n[-] Could not find Client Hello")
    client_random = None

if handshake_data["pms"] and client_random and handshake_data["server_hello"]:
    pms = handshake_data["pms"]
    server_hello = handshake_data["server_hello"]
    if len(server_hello) > 34:
        server_random = server_hello[2:34]
    else:
        print("[-] Server Hello too short")
        server_random = None
    
    if server_random:
        # Derive master secret
        master_secret = PRF_TLS12(pms, b"master secret", client_random + server_random, 48)
        print(f"\n[+] Master Secret: {master_secret.hex()}")
        
        # Derive session keys
        # For TLS 1.2 with AES-128-CBC and SHA256:
        # key_block = PRF(master_secret, "key expansion", server_random + client_random, key_block_length)
        # key_block_length = 2 * (MAC_length + encryption_key_length + IV_length)
        # For SHA256: MAC_length = 32
        # For AES-128: encryption_key_length = 16, IV_length = 16
        # Total: 2 * (32 + 16 + 16) = 128 bytes
        
        key_block = PRF_TLS12(master_secret, b"key expansion", server_random + client_random, 128)
        print(f"\n[+] Key Block (first 64 bytes): {key_block[:64].hex()}")
        
        # Parse key block
        client_write_mac = key_block[0:32]
        server_write_mac = key_block[32:64]
        client_write_key = key_block[64:80]
        server_write_key = key_block[80:96]
        client_write_iv = key_block[96:112]
        server_write_iv = key_block[112:128]
        
        print(f"\n[+] Client Write MAC: {client_write_mac.hex()}")
        print(f"[+] Server Write MAC: {server_write_mac.hex()}")
        print(f"[+] Client Write Key: {client_write_key.hex()}")
        print(f"[+] Server Write Key: {server_write_key.hex()}")
        print(f"[+] Client Write IV: {client_write_iv.hex()}")
        print(f"[+] Server Write IV: {server_write_iv.hex()}")
        
        # Now decrypt application data (from server to client)
        print(f"\n[*] Attempting to decrypt application data...")
        
        for i, payload in enumerate(tls_payloads_by_dir["server_to_client"]):
            offset = 0
            while offset < len(payload):
                record, rec_len = parse_tls_record(payload[offset:])
                if record is None:
                    break
                
                if record['type'] == 0x17:  # Application Data
                    encrypted_content = record['content']
                    print(f"\n[+] Found encrypted application data (record {i}, offset {offset})")
                    print(f"    Length: {len(encrypted_content)} bytes")
                    print(f"    First 30 bytes (hex): {encrypted_content[:30].hex()}")
                    
                    try:
                        # Extract IV (first 16 bytes for CBC mode in TLS 1.1+)
                        if len(encrypted_content) > 16:
                            iv = encrypted_content[:16]
                            ciphertext = encrypted_content[16:]
                            
                            cipher = Cipher(
                                algorithms.AES(server_write_key),
                                modes.CBC(iv),
                                backend=default_backend()
                            )
                            decryptor = cipher.decryptor()
                            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                            
                            # Remove PKCS7 padding and MAC
                            if len(plaintext) > 0:
                                padding_length = plaintext[-1]
                                if padding_length < 16:
                                    plaintext_without_padding = plaintext[:-padding_length-1]
                                    # Remove MAC (first 32 bytes after removing padding)
                                    if len(plaintext_without_padding) > 32:
                                        http_data = plaintext_without_padding[32:]
                                        print(f"    Decrypted (first 100 bytes): {http_data[:100]}")
                                        if http_data:
                                            try:
                                                print(f"    Decrypted (as text): {http_data.decode('utf-8', errors='replace')[:200]}")
                                            except:
                                                pass
                    except Exception as e:
                        print(f"    Decryption error: {e}")
                
                offset += rec_len
EOF
