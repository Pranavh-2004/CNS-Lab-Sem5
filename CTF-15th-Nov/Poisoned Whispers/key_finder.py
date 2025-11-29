#!/usr/bin/env python3
"""
Find what 32-character text key works
"""

import base64
from Crypto.Cipher import AES

encrypted_hex = "44d5742181e2a59a9bee283398f54ee2"
encrypted = bytes.fromhex(encrypted_hex)

key_b64 = "HKzbsIPa3dpvNXNn3ngFKhSGVqK2x8vD/w6xnGaLn1Y="
key_binary = base64.b64decode(key_b64)

print("="*80)
print("FINDING THE TEXT KEY")
print("="*80)

# Possibility 1: The base64 string itself (first 32 chars)
key1 = key_b64[:32].encode('utf-8')
print(f"\n1. First 32 chars of base64 string:")
print(f"   Key text: {key1.decode()}")
print(f"   Key hex: {key1.hex()}")
cipher = AES.new(key1, AES.MODE_ECB)
try:
    decrypted = cipher.decrypt(encrypted)
    text = decrypted.decode('utf-8', errors='ignore')
    print(f"   Decrypted: {repr(text)}")
    print(f"   Flag: isfcr{{ea{text}lag_2025}}")
except Exception as e:
    print(f"   Error: {e}")

# Possibility 2: HELLO repeated and padded
key2 = (b"HELLO" * 7)[:32]
print(f"\n2. 'HELLO' repeated to 32 bytes:")
print(f"   Key text: {key2.decode()}")
print(f"   Key hex: {key2.hex()}")
cipher = AES.new(key2, AES.MODE_ECB)
try:
    decrypted = cipher.decrypt(encrypted)
    text = decrypted.decode('utf-8', errors='ignore')
    print(f"   Decrypted: {repr(text)}")
    print(f"   Flag: isfcr{{ea{text}lag_2025}}")
except Exception as e:
    print(f"   Error: {e}")

# Possibility 3: Some combination
key3 = b"HKzbsIPa3dpvNXNn3ngFKhSGVqK2x8vD"
print(f"\n3. Exact first 32 chars of base64:")
print(f"   Key text: {key3.decode()}")
print(f"   Key hex: {key3.hex()}")
cipher = AES.new(key3, AES.MODE_ECB)
try:
    decrypted = cipher.decrypt(encrypted)
    text = decrypted.decode('utf-8', errors='ignore')
    print(f"   Decrypted: {repr(text)}")
    print(f"   Flag: isfcr{{ea{text}lag_2025}}")
except Exception as e:
    print(f"   Error: {e}")

# Possibility 4: The actual binary key (what we've been using)
print(f"\n4. Binary decoded key (what we've been using):")
print(f"   Key hex: {key_binary.hex()}")
cipher = AES.new(key_binary, AES.MODE_ECB)
try:
    decrypted = cipher.decrypt(encrypted)
    text = decrypted.decode('utf-8', errors='ignore')
    print(f"   Decrypted: {repr(text)}")
    print(f"   Flag: isfcr{{ea{text}lag_2025}}")
except Exception as e:
    print(f"   Error: {e}")

print("\n" + "="*80)
print("FOR THE ONLINE TOOL:")
print("="*80)
print("\nTry these keys (as text, not hex):")
print(f"1. {key_b64[:32]}")
print(f"2. {key2.decode()}")
print(f"3. HKzbsIPa3dpvNXNn3ngFKhSGVqK2x8vD")
print("\nWith encrypted text (as hex):")
print(f"   {encrypted_hex}")
print("\nMode: ECB")
print("Padding: NoPadding")
print("Output: Plain-Text")