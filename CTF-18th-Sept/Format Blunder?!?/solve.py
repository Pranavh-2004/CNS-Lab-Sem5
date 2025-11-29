# Hex fragments from your offsets
hex_fragments = [
    "54623",
    "231f44b489bb",
    "72762a4e8e",
    "c4cd7cd24e0a",
    "0ec2cbd6a5"
]

# Convert to bytes
fragments_bytes = []
for hx in hex_fragments:
    if len(hx) % 2:
        hx = "0" + hx  # pad odd-length
    fragments_bytes.append(bytes.fromhex(hx))

# Combine fragments
encrypted_flag = b"".join(fragments_bytes)
print("[+] Encrypted flag bytes:", encrypted_flag)

# Simple XOR brute-force: try all 1-byte keys (0x00-0xFF)
for key in range(256):
    decrypted = bytes(b ^ key for b in encrypted_flag)
    if b"flag{" in decrypted.lower():
        print(f"[+] Possible key: {key:#02x}")
        print("[+] Decrypted flag:", decrypted.decode())
        break
