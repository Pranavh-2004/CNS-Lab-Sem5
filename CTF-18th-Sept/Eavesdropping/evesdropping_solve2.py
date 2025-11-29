'''
import base64

fragments = [
    "YjNz",   # 2
    "aXNm",   # 0
    "bmQ1",   # 5
    "zdj",    # 7
    "Y3J7",   # 1
    "Q==",    # 9
    "dF9m",   # 3
    "cjEz",   # 4
    "XzQ",    # 6
    "Nyf"     # 8
]

# Combine according to ORDER: [2,0,5,7,1,9,3,4,6,8]
combined = "".join(frag.strip("=") for frag in fragments)

# Add padding if needed
padding = 4 - (len(combined) % 4)
if padding != 4:
    combined += "=" * padding

decoded = base64.b64decode(combined)
print(decoded.decode())
'''

'''
import base64

fragments = [
    "YjNz", "aXNm", "bmQ1", "zdj", "Y3J7", "Q==", "dF9m", "cjEz", "XzQ", "Nyf"
]

# Combine and fix padding
combined = "".join(frag.strip("=") for frag in fragments)
padding = 4 - (len(combined) % 4)
if padding != 4:
    combined += "=" * padding

decoded = base64.b64decode(combined)
print(decoded)  # raw bytes
'''

'''
import base64

# Fragments by index
fragments = {
    0: "aXNm",
    1: "Y3J7",
    2: "YjNz",
    3: "dF9m",
    4: "cjEz",
    5: "bmQ1",
    6: "XzQ",
    7: "zdj",
    8: "Nyf",
    9: "Q=="
}

# ORDER from the server
ORDER = [2, 0, 5, 7, 1, 9, 3, 4, 6, 8]

# Combine fragments in the correct order
combined = ''.join(fragments[i] for i in ORDER)

# Fix Base64 padding if needed
padding = (4 - len(combined) % 4) % 4
combined += "=" * padding

print("[+] Combined Base64 string:")
print(combined)

# Decode
decoded = base64.b64decode(combined)
print("\n[+] Decoded bytes:")
print(decoded)

# Decode to ASCII ignoring errors
flag = decoded.decode(errors='ignore')
print("\n[+] Flag (ASCII, ignoring errors):")
print(flag)
'''

'''
import base64

# Fragments by index
fragments = {
    0: "aXNm",
    1: "Y3J7",
    2: "YjNz",
    3: "dF9m",
    4: "cjEz",
    5: "bmQ1",
    6: "XzQ",
    7: "zdj",
    8: "Nyf",
    9: "Q=="
}

# ORDER from the server
ORDER = [2, 0, 5, 7, 1, 9, 3, 4, 6, 8]

# Combine fragments in the correct order
combined = ''.join(fragments[i].rstrip('=') for i in ORDER)

# Fix Base64 padding at the end
padding = (4 - len(combined) % 4) % 4
combined += "=" * padding

print("[+] Combined Base64 string (corrected padding):")
print(combined)

# Decode
decoded = base64.b64decode(combined)
print("\n[+] Decoded bytes:")
print(decoded)

# Decode to ASCII ignoring errors
flag = decoded.decode(errors='ignore')
print("\n[+] Flag (ASCII, ignoring errors):")
print(flag)
'''

'''
import base64
import string

# Fragments by index
fragments = {
    0: "aXNm",
    1: "Y3J7",
    2: "YjNz",
    3: "dF9m",
    4: "cjEz",
    5: "bmQ1",
    6: "XzQ",
    7: "zdj",
    8: "Nyf",
    9: "Q=="
}

ORDER = [2, 0, 5, 7, 1, 9, 3, 4, 6, 8]

# Combine fragments in correct order (strip internal padding)
combined = ''.join(fragments[i].rstrip('=') for i in ORDER)

# Fix Base64 padding at the end
padding = (4 - len(combined) % 4) % 4
combined += "=" * padding

# Decode
decoded_bytes = base64.b64decode(combined)

# Extract only printable ASCII characters (typical for CTF flags)
printable_flag = ''.join(chr(b) for b in decoded_bytes if chr(b) in string.printable)

print("[+] Raw decoded bytes:")
print(decoded_bytes)

print("\n[+] Printable ASCII flag portion:")
print(printable_flag)
'''

'''
import base64

s = "YjNzaXNmbmQ1zdjY3J7Q==dF9mcjEzXzQNyf"


# Add padding
padding = (4 - len(s) % 4) % 4
s += "=" * padding
decoded = base64.b64decode(s)
print(decoded)
'''

'''
import base64

# Combined fragments (from your ORDER array)
combined = "YjNzaXNmbmQ1zdjY3J7Q==dF9mcjEzXzQNyf"

# Remove any non-Base64 chars that could break decoding (optional)
combined = combined.replace("\n", "").replace(" ", "")

# Fix padding: Base64 length must be multiple of 4
padding_needed = (4 - len(combined) % 4) % 4
combined += "=" * padding_needed

# Decode
try:
    decoded_bytes = base64.b64decode(combined)
    print("[+] Decoded bytes:", decoded_bytes)
    print("[+] Flag (ASCII, ignoring errors):", decoded_bytes.decode(errors='ignore'))
except Exception as e:
    print("[!] Failed to decode:", e)
    '''

'''
import base64

# fragments captured in ORDER
fragments = [
    "YjNz",    # 2
    "aXNm",    # 0
    "bmQ1",    # 5
    "zdj",     # 7
    "Y3J7",    # 1
    "Q==",     # 9
    "dF9m",    # 3
    "cjEz",    # 4
    "XzQ",     # 6
    "Nyf"      # 8
]

# ORDER in which they should be combined
ORDER = [2,0,5,7,1,9,3,4,6,8]

decoded_bytes = b""

for idx in ORDER:
    frag = fragments[idx]
    # fix padding for each fragment individually
    padding_needed = (4 - len(frag) % 4) % 4
    frag += "=" * padding_needed
    decoded_bytes += base64.b64decode(frag)

print("[+] Decoded bytes:", decoded_bytes)
print("[+] Flag (ASCII, ignoring errors):", decoded_bytes.decode(errors='ignore'))
'''
'''
import base64

# Captured fragments in their original indices
fragments = [
    "aXNm",  # 0
    "Y3J7",  # 1
    "YjNz",  # 2
    "dF9m",  # 3
    "cjEz",  # 4
    "bmQ1",  # 5
    "XzQ",   # 6
    "zdj",   # 7
    "Nyf",   # 8
    "Q=="    # 9
]

# Correct order to assemble
ORDER = [2, 0, 5, 7, 1, 9, 3, 4, 6, 8]

decoded_bytes = b""

for idx in ORDER:
    frag = fragments[idx]

    # Remove whitespace/newlines
    frag = frag.strip()

    # Calculate padding
    padding_needed = (4 - len(frag) % 4) % 4
    frag += "=" * padding_needed

    try:
        decoded_bytes += base64.b64decode(frag, validate=True)
    except Exception as e:
        print(f"[!] Failed to decode fragment {idx}: {frag} ({e})")

print("[+] Decoded bytes:", decoded_bytes)
print("[+] Flag (ASCII, ignoring errors):", decoded_bytes.decode(errors='ignore'))
'''

import base64

s = "aXNmY3J7YjNzdF9mcjEzbmQ1XzQzdjNyfQ==" 


# Add padding
padding = (4 - len(s) % 4) % 4
s += "=" * padding
decoded = base64.b64decode(s)
print(decoded)