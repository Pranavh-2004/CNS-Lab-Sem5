#!/usr/bin/env python3
"""
DNS Poisoning CTF Challenge - Flag Reconstructor
Decrypts and reconstructs the flag from poisoned DNS responses
"""

import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_aes(ciphertext, key):
    """
    Try different AES modes to decrypt the ciphertext
    """
    print(f"\n[*] Attempting AES decryption...")
    print(f"[*] Ciphertext length: {len(ciphertext)} bytes")
    print(f"[*] Key length: {len(key)} bytes")
    
    # Try ECB mode (no IV needed)
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
        # Try to unpad
        try:
            decrypted_unpadded = unpad(decrypted, AES.block_size)
            print(f"[+] ECB mode (with unpadding) successful!")
            return decrypted_unpadded.decode('utf-8', errors='ignore')
        except:
            # Return without unpadding
            print(f"[+] ECB mode (no padding) successful!")
            return decrypted.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[-] ECB mode failed: {e}")
    
    # Try CBC mode with zero IV
    try:
        iv = b'\x00' * 16
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        try:
            decrypted_unpadded = unpad(decrypted, AES.block_size)
            print(f"[+] CBC mode with zero IV (with unpadding) successful!")
            return decrypted_unpadded.decode('utf-8', errors='ignore')
        except:
            print(f"[+] CBC mode with zero IV (no padding) successful!")
            return decrypted.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[-] CBC mode with zero IV failed: {e}")
    
    return None

def main():
    print("="*60)
    print("DNS Poisoning CTF - Flag Reconstructor")
    print("="*60)
    
    # Part 1: Base64 encoded data from Frame 74 (1.2.3.101)
    part1_b64 = "aXNmY3J7ZWE="
    part1 = base64.b64decode(part1_b64).decode('utf-8')
    print(f"\n[+] Part 1 (Frame 74 - Base64): {part1}")
    
    # Part 2: Encrypted data from Frame 73 (1.2.3.102)
    # TXT: D�t!������(3��N�
    # These are the hex bytes from the TXT record (16 bytes)
    part2_encrypted_hex = "44f374219fb8f1f9e0e12833cfe84ee7"
    part2_encrypted = bytes.fromhex(part2_encrypted_hex)
    print(f"\n[+] Part 2 (Frame 73 - Encrypted): {part2_encrypted.hex()}")
    
    # Part 3: Plain text from Frame 77 (1.2.3.103) - needs to be reversed
    part3_reversed = "}5202_gal"
    part3 = part3_reversed[::-1]  # Reverse it
    print(f"\n[+] Part 3 (Frame 77 - Reversed): {part3}")
    
    # Decryption key from HTTP header (Frame 55)
    key_b64 = "HKzbsIPa3dpvNXNn3ngFKhSGVqK2x8vD/w6xnGaLn1Y="
    key = base64.b64decode(key_b64)
    print(f"\n[+] AES Key from HTTP header (X-Session-Key): {key_b64}")
    print(f"[+] Key (hex): {key.hex()}")
    
    # Decrypt part 2
    part2_decrypted = decrypt_aes(part2_encrypted, key)
    
    if part2_decrypted:
        print(f"\n[+] Part 2 (Decrypted): {part2_decrypted}")
        
        # Reconstruct the full flag
        flag = part1 + part2_decrypted + part3
        print("\n" + "="*60)
        print(f"[SUCCESS] FLAG: {flag}")
        print("="*60)
    else:
        print("\n[-] Decryption failed. Trying alternative interpretation...")
        print(f"\n[*] Flag structure: {part1} + [encrypted_part] + {part3}")
        
        # Try interpreting the encrypted bytes differently
        print(f"\n[*] Encrypted bytes as ASCII (might be garbled): {part2_encrypted}")

if __name__ == "__main__":
    main()