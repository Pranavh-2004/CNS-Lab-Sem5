#!/usr/bin/env python3
"""
Final attempt - trying all reasonable combinations
"""

import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Confirmed data
part1_b64 = "aXNmY3J7ZWE="  # Frame 74
part2_hex = "44d5742181e2a59a9bee283398f54ee2"  # Frame 73 - CONFIRMED CORRECT
part3_text = "}5202_gal"  # Frame 77

# Key and IV
key_b64 = "HKzbsIPa3dpvNXNn3ngFKhSGVqK2x8vD/w6xnGaLn1Y="
key = base64.b64decode(key_b64)
iv_hello = b"HELLO"

print("="*80)
print("FINAL DECRYPTION ATTEMPT - CONFIRMED DATA")
print("="*80)
print(f"Part 1 (Frame 74): {part1_b64} -> {base64.b64decode(part1_b64).decode()}")
print(f"Part 2 (Frame 73): {part2_hex} (16 bytes encrypted)")
print(f"Part 3 (Frame 77): {part3_text}")
print(f"Session Key: {key_b64}")
print(f"HTTP Data (IV?): {iv_hello.decode()}")
print("="*80)

part1 = base64.b64decode(part1_b64).decode('utf-8')
part2_encrypted = bytes.fromhex(part2_hex)
part3_reversed = part3_text[::-1]

def try_decrypt(key, iv, mode_name):
    """Try decryption and return result"""
    results = []
    
    # AES-256
    try:
        if iv is None:
            cipher = AES.new(key, AES.MODE_ECB)
        else:
            cipher = AES.new(key, AES.MODE_CBC, iv)
        
        decrypted = cipher.decrypt(part2_encrypted)
        
        # Try with unpadding
        try:
            unpadded = unpad(decrypted, AES.block_size)
            text = unpadded.decode('utf-8', errors='ignore')
            results.append((f"{mode_name} (unpadded)", text))
        except:
            pass
        
        # Try without unpadding
        text = decrypted.decode('utf-8', errors='ignore')
        results.append((f"{mode_name}", text))
        
    except Exception as e:
        results.append((f"{mode_name}", f"ERROR: {e}"))
    
    # AES-128 (first 16 bytes of key)
    try:
        key_128 = key[:16]
        if iv is None:
            cipher = AES.new(key_128, AES.MODE_ECB)
        else:
            cipher = AES.new(key_128, AES.MODE_CBC, iv[:16] if len(iv) > 16 else iv)
        
        decrypted = cipher.decrypt(part2_encrypted)
        text = decrypted.decode('utf-8', errors='ignore')
        results.append((f"{mode_name} [AES-128]", text))
    except Exception as e:
        results.append((f"{mode_name} [AES-128]", f"ERROR: {e}"))
    
    return results

print("\n" + "="*80)
print("TRYING ALL CIPHER MODES AND IV OPTIONS:")
print("="*80)

test_cases = [
    ("ECB (no IV)", None),
    ("CBC with zero IV", b'\x00' * 16),
    ("CBC with HELLO + zeros", iv_hello + b'\x00' * 11),
    ("CBC with HELLO repeated", (iv_hello * 4)[:16]),
    ("CBC with key[:16] as IV", key[:16]),
]

all_flags = []

for desc, iv in test_cases:
    print(f"\n{desc}:")
    if iv:
        print(f"  IV (hex): {iv.hex()}")
    
    results = try_decrypt(key, iv, desc)
    
    for mode, decrypted_text in results:
        # Try both orderings
        flag1 = part1 + decrypted_text + part3_reversed
        flag2 = part1 + decrypted_text + part3_text
        
        print(f"\n  [{mode}]")
        print(f"    Decrypted middle: {repr(decrypted_text)}")
        print(f"    Flag (Part3 reversed): {flag1}")
        print(f"    Flag (Part3 normal):   {flag2}")
        
        # Check if valid
        for flag in [flag1, flag2]:
            if flag.startswith("isfcr{") and flag.endswith("}"):
                # Check if all characters are printable
                if all(32 <= ord(c) < 127 for c in flag):
                    print(f"    ✓✓✓ VALID FLAG FORMAT AND ALL PRINTABLE! ✓✓✓")
                    all_flags.append((mode, flag))

if all_flags:
    print("\n" + "="*80)
    print("POTENTIAL VALID FLAGS:")
    print("="*80)
    for mode, flag in all_flags:
        print(f"[{mode}]")
        print(f"  {flag}")
        print()

print("\n" + "="*80)
print("RAW DECRYPTED BYTES (for analysis):")
print("="*80)
cipher = AES.new(key, AES.MODE_ECB)
raw_bytes = cipher.decrypt(part2_encrypted)
print(f"Hex: {raw_bytes.hex()}")
print(f"Bytes: {raw_bytes}")
print(f"Each byte: {[hex(b) for b in raw_bytes]}")