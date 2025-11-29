'''
#!/usr/bin/env python3
from itertools import product

# Replace with all hex fragments you collected
hex_fragments = [
    "54623",
    "231f44b489bb",
    "72762a4e8e",
    "c4cd7cd24e0a",
    "0ec2cbd6a5"
]

# Convert hex fragments to bytes
fragments_bytes = []
for hx in hex_fragments:
    if len(hx) % 2:
        hx = "0" + hx  # pad odd-length
    fragments_bytes.append(bytes.fromhex(hx))

# Function to XOR decrypt with repeating key
def xor_decrypt(data, key_bytes):
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))

# Function to check if bytes are mostly printable ASCII
def is_printable(b, threshold=0.8):
    printable = sum(32 <= c < 127 for c in b)
    return printable / max(1, len(b)) >= threshold

decrypted_fragments = []

# Try keys of length 1–3 per fragment
for idx, fragment in enumerate(fragments_bytes):
    found = False
    for key_len in range(1, 4):
        for key_tuple in product(range(256), repeat=key_len):
            key_bytes = bytes(key_tuple)
            decrypted = xor_decrypt(fragment, key_bytes)
            if is_printable(decrypted):
                print(f"[+] Fragment {idx+1} decrypted with key {key_bytes}: {decrypted.decode()}")
                decrypted_fragments.append(decrypted)
                found = True
                break
        if found:
            break
    if not found:
        print(f"[!] Fragment {idx+1} could not be decrypted with 1–3 byte XOR key")
        decrypted_fragments.append(fragment)

# Combine all decrypted fragments
full_flag = b"".join(decrypted_fragments)
print("\n[+] Full decrypted flag (combined fragments):")
try:
    print(full_flag.decode())
except:
    print("[!] Non-ASCII characters present, printing raw bytes:")
    print(full_flag)
'''

'''
#!/usr/bin/env python3
from itertools import product

hex_fragments = [
    "54623",
    "231f44b489bb",
    "72762a4e8e",
    "c4cd7cd24e0a",
    "0ec2cbd6a5"
]

# Convert hex fragments to bytes
fragments_bytes = []
for hx in hex_fragments:
    if len(hx) % 2:
        hx = "0" + hx
    fragments_bytes.append(bytes.fromhex(hx))

def xor_decrypt(data, key_bytes):
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))

def is_printable(b, threshold=0.8):
    printable = sum(32 <= c < 127 for c in b)
    return printable / max(1, len(b)) >= threshold

decrypted_fragments = []

for idx, fragment in enumerate(fragments_bytes):
    found = False
    for key_len in range(1, 4):
        for key_tuple in product(range(256), repeat=key_len):
            key_bytes = bytes(key_tuple)
            decrypted = xor_decrypt(fragment, key_bytes)
            if is_printable(decrypted):
                try:
                    print(f"[+] Fragment {idx+1} decrypted with key {key_bytes}: {decrypted.decode()}")
                except UnicodeDecodeError:
                    print(f"[+] Fragment {idx+1} decrypted with key {key_bytes} (non-ASCII): {decrypted}")
                decrypted_fragments.append(decrypted)
                found = True
                break
        if found:
            break
    if not found:
        print(f"[!] Fragment {idx+1} could not be decrypted with 1–3 byte XOR key")
        decrypted_fragments.append(fragment)

# Combine all decrypted fragments
full_flag = b"".join(decrypted_fragments)
print("\n[+] Full decrypted flag (combined fragments):")
try:
    print(full_flag.decode())
except UnicodeDecodeError:
    print("[!] Non-ASCII characters present, printing raw bytes:")
    print(full_flag)
'''

#!/usr/bin/env python3
from itertools import product

# Replace with all hex fragments you collected
hex_fragments = [
    "54623",
    "231f44b489bb",
    "72762a4e8e",
    "c4cd7cd24e0a",
    "0ec2cbd6a5"
]

# Convert hex fragments to bytes
fragments_bytes = []
for hx in hex_fragments:
    if len(hx) % 2:
        hx = "0" + hx
    fragments_bytes.append(bytes.fromhex(hx))

def xor_decrypt(data, key_bytes):
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))

def is_mostly_printable(b, threshold=0.7):
    printable = sum(32 <= c < 127 for c in b)
    return printable / max(1, len(b)) >= threshold

# Store the best candidate per fragment
best_candidates = []

for idx, fragment in enumerate(fragments_bytes):
    candidates = []
    print(f"\n[*] Brute-forcing fragment {idx+1} (length {len(fragment)})...")
    for key_len in range(1, 5):  # try keys 1-4 bytes
        for key_tuple in product(range(256), repeat=key_len):
            key_bytes = bytes(key_tuple)
            decrypted = xor_decrypt(fragment, key_bytes)
            if is_mostly_printable(decrypted):
                candidates.append((key_bytes, decrypted))
    if candidates:
        # pick the first candidate as the “best” for now
        best_key, best_decrypted = candidates[0]
        try:
            print(f"[+] Fragment {idx+1} decrypted with key {best_key}: {best_decrypted.decode()}")
        except UnicodeDecodeError:
            print(f"[+] Fragment {idx+1} decrypted with key {best_key} (non-ASCII): {best_decrypted}")
        best_candidates.append(best_decrypted)
    else:
        print(f"[!] Fragment {idx+1}: no mostly-printable candidate found, keeping original bytes")
        best_candidates.append(fragment)

# Combine all decrypted fragments
full_flag = b"".join(best_candidates)
print("\n[+] Full decrypted flag (combined fragments):")
try:
    print(full_flag.decode())
except UnicodeDecodeError:
    print("[!] Non-ASCII characters present, printing raw bytes:")
    print(full_flag)
