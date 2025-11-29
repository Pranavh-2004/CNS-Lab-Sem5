import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# The parts
part1_base64 = "aXNmY3J7ZWE="
part2_encrypted = b'D\xc9t!\x90\xa8\xfb\xff\xff(\x83\xb3\xfeN\xc2'
part3_plaintext = "}5202_gal"

# The key from HTTP header
x_session_key = "HKzbsIPa3dpvNXNn3ngFKhSGVqK2x8vD/w6xnGaLn1Y="

# Process
decoded_key = base64.b64decode(x_session_key)
aes_key = decoded_key[:16]  # Use first 16 bytes for AES-128

# Decrypt part2
cipher = AES.new(aes_key, AES.MODE_ECB)
decrypted_part2 = cipher.decrypt(part2_encrypted)

# The decrypted data might have padding, try to remove it
try:
    decrypted_part2_clean = unpad(decrypted_part2, AES.block_size)
except:
    decrypted_part2_clean = decrypted_part2.rstrip(b'\x00')

decrypted_text = decrypted_part2_clean.decode('ascii')

# Decode part1
decoded_part1 = base64.b64decode(part1_base64).decode('ascii')

# Combine all parts
flag = decoded_part1 + decrypted_text + part3_plaintext
print(f"FLAG: {flag}")