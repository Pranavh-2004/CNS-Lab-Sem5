#!/usr/bin/env python3
"""
Full TLS decryption with TCP stream reassembly
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

# Reconstruct TCP streams
tcp_streams = {}
for pkt in packets:
    if TCP in pkt and Raw in pkt:
        if pkt[TCP].dport == 4443:
            direction = "C2S"  # Client to Server
        else:
            direction = "S2C"  # Server to Client
        
        stream_id = direction
        if stream_id not in tcp_streams:
            tcp_streams[stream_id] = b""
        
        tcp_streams[stream_id] += bytes(pkt[Raw].load)

print(f"[*] Reconstructed TCP streams:")
for stream_id, data in tcp_streams.items():
    print(f"    {stream_id}: {len(data)} bytes")

# Parse handshake messages from C2S stream
handshake_data = {
    "client_hello": None,
    "server_hello": None,
    "pms": None,
}

print(f"\n[*] Parsing Client->Server stream...")
offset = 0
while offset < len(tcp_streams["C2S"]):
    record, rec_len = parse_tls_record(tcp_streams["C2S"][offset:])
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
                print(f"[+] Found Client Hello ({len(hs_content)} bytes)")
            
            elif hs_type == 16 and handshake_data["pms"] is None:  # Client Key Exchange
                if len(hs_content) > 2:
                    pms_len = (hs_content[0] << 8) | hs_content[1]
                    encrypted_pms = hs_content[2:2+pms_len]
                    
                    try:
                        pms = private_key.decrypt(encrypted_pms, padding.PKCS1v15())
                        handshake_data["pms"] = pms
                        print(f"[+] Decrypted PMS: {pms.hex()}")
                    except Exception as e:
                        print(f"[-] Decryption failed: {e}")
    
    offset += rec_len

# Parse handshake messages from S2C stream
print(f"\n[*] Parsing Server->Client stream...")
offset = 0
while offset < len(tcp_streams["S2C"]):
    record, rec_len = parse_tls_record(tcp_streams["S2C"][offset:])
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
                print(f"[+] Found Server Hello ({len(hs_content)} bytes)")
    
    offset += rec_len

# Extract random values
if handshake_data["client_hello"] and len(handshake_data["client_hello"]) > 34:
    client_random = handshake_data["client_hello"][2:34]
    print(f"\n[+] Client Random: {client_random.hex()}")
else:
    print("\n[-] Could not extract Client Random")
    client_random = None

if handshake_data["server_hello"] and len(handshake_data["server_hello"]) > 34:
    server_random = handshake_data["server_hello"][2:34]
    print(f"[+] Server Random: {server_random.hex()}")
else:
    print("[-] Could not extract Server Random")
    server_random = None

# Derive session keys
if handshake_data["pms"] and client_random and server_random:
    pms = handshake_data["pms"]
    
    # Derive master secret
    master_secret = PRF_TLS12(pms, b"master secret", client_random + server_random, 48)
    print(f"\n[+] Master Secret: {master_secret.hex()}")
    
    # Derive key block
    key_block = PRF_TLS12(master_secret, b"key expansion", server_random + client_random, 128)
    
    # Parse key block
    client_write_mac = key_block[0:32]
    server_write_mac = key_block[32:64]
    client_write_key = key_block[64:80]
    server_write_key = key_block[80:96]
    client_write_iv = key_block[96:112]
    server_write_iv = key_block[112:128]
    
    print(f"[+] Server Write Key: {server_write_key.hex()}")
    print(f"[+] Server Write IV: {server_write_iv.hex()}")
    print(f"[+] Server Write MAC: {server_write_mac.hex()}")
    
    # Decrypt application data from S2C stream
    print(f"\n[*] Decrypting application data...")
    offset = 0
    decrypted_data = b""
    
    while offset < len(tcp_streams["S2C"]):
        record, rec_len = parse_tls_record(tcp_streams["S2C"][offset:])
        if record is None:
            break
        
        if record['type'] == 0x17:  # Application Data
            encrypted_content = record['content']
            
            try:
                # For TLS 1.2 with CBC mode, IV is part of the encrypted content (explicit IV)
                if len(encrypted_content) > 16:
                    iv = encrypted_content[:16]
                    ciphertext = encrypted_content[16:]
                    
                    # Ensure ciphertext is a multiple of block size
                    if len(ciphertext) % 16 == 0:
                        cipher = Cipher(
                            algorithms.AES(server_write_key),
                            modes.CBC(iv),
                            backend=default_backend()
                        )
                        decryptor = cipher.decryptor()
                        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                        
                        # Remove PKCS7 padding
                        if len(plaintext) > 0:
                            padding_length = plaintext[-1]
                            if 0 <= padding_length < 16:
                                # Remove padding and MAC
                                plaintext_without_padding_and_mac = plaintext[:(len(plaintext) - padding_length - 1 - 32)]
                                decrypted_data += plaintext_without_padding_and_mac
                                print(f"[+] Decrypted record: {len(plaintext_without_padding_and_mac)} bytes")
            except Exception as e:
                print(f"[-] Decryption error: {e}")
        
        offset += rec_len
    
    if decrypted_data:
        print(f"\n[+] Total decrypted: {len(decrypted_data)} bytes")
        print(f"\n[+] Decrypted content (first 500 bytes):")
        print(decrypted_data[:500])
        print(f"\n[+] Decrypted content (as text, first 500 chars):")
        try:
            print(decrypted_data[:500].decode('utf-8', errors='replace'))
        except:
            pass
        
        # Save to file
        with open("decrypted_data.txt", "wb") as f:
            f.write(decrypted_data)
        print(f"\n[+] Saved to decrypted_data.txt")
