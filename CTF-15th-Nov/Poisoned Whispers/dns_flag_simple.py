#!/usr/bin/env python3
"""
Simple DNS Flag Decryptor - Testing with HELLO as IV
"""

import base64
from Crypto.Cipher import AES

# Parts from DNS responses
part1_b64 = "aXNmY3J7ZWE="
part1 = base64.b64decode(part1_b64).decode('utf-8')
print(f"Part 1: {part1}")

part3_reversed = "}5202_gal"
part3 = part3_reversed[::-1]
print(f"Part 3: {part3}")

# Encrypted part from Frame 73
part2_hex = "44d5742181e2a59a9bee283398f54ee2"
part2_encrypted = bytes.fromhex(part2_hex)
print(f"Part 2 (encrypted hex): {part2_hex}")

# Key from HTTP header
key_b64 = "HKzbsIPa3dpvNXNn3ngFKhSGVqK2x8vD/w6xnGaLn1Y="
key = base64.b64decode(key_b64)
print(f"Key: {key_b64}")

# HTTP file data - potential IV
http_data = b"HELLO"
print(f"\nHTTP File Data: {http_data.decode()}")

print("\n" + "="*70)
print("TESTING DECRYPTION WITH DIFFERENT IV OPTIONS:")
print("="*70)

# Test 1: ECB mode (no IV)
print("\n1. ECB mode (no IV):")
cipher = AES.new(key, AES.MODE_ECB)
decrypted = cipher.decrypt(part2_encrypted)
part2_decrypted = decrypted.decode('utf-8', errors='ignore')
flag = part1 + part2_decrypted + part3
print(f"   Decrypted: {repr(part2_decrypted)}")
print(f"   Flag: {flag}")

# Test 2: CBC with HELLO padded with zeros
print("\n2. CBC mode with 'HELLO' + zero padding as IV:")
iv = http_data + b'\x00' * 11  # Pad to 16 bytes
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(part2_encrypted)
part2_decrypted = decrypted.decode('utf-8', errors='ignore')
flag = part1 + part2_decrypted + part3
print(f"   IV (hex): {iv.hex()}")
print(f"   Decrypted: {repr(part2_decrypted)}")
print(f"   Flag: {flag}")

# Test 3: CBC with HELLO repeated
print("\n3. CBC mode with 'HELLO' repeated to 16 bytes:")
iv = (http_data * 4)[:16]  # HELLOHELLOHELLOH
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(part2_encrypted)
part2_decrypted = decrypted.decode('utf-8', errors='ignore')
flag = part1 + part2_decrypted + part3
print(f"   IV (hex): {iv.hex()}")
print(f"   IV (ascii): {iv}")
print(f"   Decrypted: {repr(part2_decrypted)}")
print(f"   Flag: {flag}")

# Test 4: CBC with zero IV (baseline)
print("\n4. CBC mode with zero IV (baseline):")
iv = b'\x00' * 16
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(part2_encrypted)
part2_decrypted = decrypted.decode('utf-8', errors='ignore')
flag = part1 + part2_decrypted + part3
print(f"   Decrypted: {repr(part2_decrypted)}")
print(f"   Flag: {flag}")

# Test 5: Try using HELLO as part of the key instead
print("\n5. Testing if HELLO modifies the key:")
modified_key = bytes([a ^ b for a, b in zip(key, (http_data * 7)[:32])])
cipher = AES.new(modified_key, AES.MODE_ECB)
decrypted = cipher.decrypt(part2_encrypted)
part2_decrypted = decrypted.decode('utf-8', errors='ignore')
flag = part1 + part2_decrypted + part3
print(f"   Decrypted: {repr(part2_decrypted)}")
print(f"   Flag: {flag}")

print("\n" + "="*70)