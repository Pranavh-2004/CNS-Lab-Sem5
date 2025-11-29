#!/usr/bin/env python3
"""
DNS Poisoning CTF Challenge - Flag Reconstructor (Enhanced)
Decrypts and reconstructs the flag from poisoned DNS responses
"""

import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

def decrypt_aes_all_modes(ciphertext, key):
    """
    Try all common AES modes and configurations
    """
    print(f"\n[*] Attempting AES decryption...")
    print(f"[*] Ciphertext length: {len(ciphertext)} bytes")
    print(f"[*] Key length: {len(key)} bytes")
    print(f"[*] Ciphertext (hex): {ciphertext.hex()}")
    
    results = []
    
    # Try ECB mode
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
        # Try both with and without unpadding
        try:
            decrypted_unpadded = unpad(decrypted, AES.block_size)
            result = decrypted_unpadded.decode('utf-8', errors='ignore')
            results.append(("ECB (unpadded)", result))
        except:
            pass
        result = decrypted.decode('utf-8', errors='ignore')
        results.append(("ECB (raw)", result))
    except Exception as e:
        print(f"[-] ECB mode error: {e}")
    
    # Try CBC mode with different IVs
    iv_options = [
        (b'\x00' * 16, "zero IV"),
        (key[:16], "first 16 bytes of key as IV"),
        (b'\x10' * 16, "0x10 repeated"),
        (b'HELLO' + b'\x00' * 11, "HELLO + zero padding"),
        (b'HELLO' * 3 + b'H', "HELLO repeated to 16 bytes"),
    ]
    
    for iv, iv_desc in iv_options:
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            try:
                decrypted_unpadded = unpad(decrypted, AES.block_size)
                result = decrypted_unpadded.decode('utf-8', errors='ignore')
                results.append((f"CBC with {iv_desc} (unpadded)", result))
            except:
                pass
            result = decrypted.decode('utf-8', errors='ignore')
            results.append((f"CBC with {iv_desc} (raw)", result))
        except Exception as e:
            print(f"[-] CBC mode with {iv_desc} error: {e}")
    
    return results

def extract_hex_from_txt():
    """
    Helper to show how to extract the actual TXT data
    """
    print("\n[!] To extract exact bytes from Frame 73, use:")
    print("    tshark -r <pcap> -Y 'frame.number==73' -T fields -e dns.txt")
    print("    OR")
    print("    tshark -r <pcap> -Y 'frame.number==73' -T fields -e dns.txt | xxd -r -p | xxd")
    print("    OR check the reassembled data field")
    print("\n[!] Also verify the order - maybe the parts are assembled differently!")
    print("    Try: [Part3] + [Part2] + [Part1] or other combinations")

def main():
    print("="*70)
    print("DNS Poisoning CTF - Flag Reconstructor (Enhanced)")
    print("="*70)
    
    # Part 1: Base64 encoded data from Frame 74 (1.2.3.101)
    part1_b64 = "aXNmY3J7ZWE="
    part1 = base64.b64decode(part1_b64).decode('utf-8')
    print(f"\n[+] Part 1 (Frame 74 - 1.2.3.101 - Base64): {part1}")
    
    # Part 3: Plain text from Frame 77 (1.2.3.103) - needs to be reversed
    part3_reversed = "}5202_gal"
    part3 = part3_reversed[::-1]
    print(f"[+] Part 3 (Frame 77 - 1.2.3.103 - Reversed): {part3}")
    
    # Decryption key from HTTP header (Frame 55)
    key_b64 = "HKzbsIPa3dpvNXNn3ngFKhSGVqK2x8vD/w6xnGaLn1Y="
    key = base64.b64decode(key_b64)
    print(f"\n[+] AES Key from HTTP header: {key_b64}")
    print(f"[+] Key (hex): {key.hex()}")
    
    print("\n" + "-"*70)
    print("TESTING DIFFERENT ENCRYPTED DATA INTERPRETATIONS:")
    print("-"*70)
    
    # Try different interpretations of the encrypted bytes from Frame 73
    encrypted_candidates = [
        # Correct hex from reassembled data
        ("CORRECT - From reassembled data", "44d5742181e2a59a9bee283398f54ee2"),
        # Original attempt (wrong)
        ("Wrong interpretation", "44f374219fb8f1f9e0e12833cfe84ee7"),
    ]
    
    # Add more candidates by trying to interpret the visible string
    txt_visible = "D�t!������(3��N�"
    try:
        encrypted_candidates.append(("Latin-1 encoding", txt_visible.encode('latin-1').hex()))
    except:
        pass
    
    # Try interpreting as the actual hex bytes that might be in the pcap
    # The TXT record shows "TXT Length: 16" so it's 16 bytes
    
    for desc, hex_data in encrypted_candidates:
        print(f"\n{'='*70}")
        print(f"Testing: {desc}")
        print(f"Hex: {hex_data}")
        print(f"{'='*70}")
        
        try:
            part2_encrypted = bytes.fromhex(hex_data)
            results = decrypt_aes_all_modes(part2_encrypted, key)
            
            print(f"\n[*] Decryption attempts for {desc}:")
            for mode, decrypted in results:
                flag = part1 + decrypted + part3
                print(f"    [{mode}]")
                print(f"    Decrypted: {repr(decrypted)}")
                print(f"    Full flag: {flag}")
                
                # Check if it looks like a valid flag
                if flag.startswith("isfcr{") and flag.endswith("}") and all(32 <= ord(c) < 127 for c in flag):
                    print(f"    ✓ LOOKS VALID!")
                print()
        
        except Exception as e:
            print(f"[-] Error: {e}")
    
    print("\n" + "="*70)
    print("TRYING DIFFERENT PART ORDERS:")
    print("="*70)
    
    # Try different orderings of the parts
    part2_hex = "44d5742181e2a59a9bee283398f54ee2"
    part2_encrypted = bytes.fromhex(part2_hex)
    
    # Try ECB mode for each ordering
    cipher = AES.new(key, AES.MODE_ECB)
    part2_decrypted = cipher.decrypt(part2_encrypted).decode('utf-8', errors='ignore')
    
    orderings = [
        ("1-2-3", part1 + part2_decrypted + part3),
        ("1-3-2", part1 + part3 + part2_decrypted),
        ("2-1-3", part2_decrypted + part1 + part3),
        ("2-3-1", part2_decrypted + part3 + part1),
        ("3-1-2", part3 + part1 + part2_decrypted),
        ("3-2-1", part3 + part2_decrypted + part1),
    ]
    
    print("\nTrying different part orderings with ECB decryption:")
    for order, flag in orderings:
        print(f"  Order {order}: {flag}")
        if flag.startswith("isfcr{") and flag.endswith("}"):
            print(f"    ✓ Valid flag format!")
    
    print("\n" + "="*70)
    print("[!] ADDITIONAL DEBUGGING:")
    print("="*70)
    extract_hex_from_txt()
    print("\n[!] Check if there's additional context in the HTTP response (Frame 55)")
    print("[!] The text 'Here is the key' might contain another clue")

if __name__ == "__main__":
    main()