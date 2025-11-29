from scapy.all import rdpcap, Raw

def caesar(text, shift):
    result = ""
    for ch in text:
        if ch.isalpha():
            base = 'A' if ch.isupper() else 'a'
            result += chr((ord(ch) - ord(base) + shift) % 26 + ord(base))
        else:
            result += ch
    return result

# Load packets
packets = rdpcap("Lisa.pcap")

all_payloads = []
for pkt in packets:
    if pkt.haslayer(Raw):
        raw_data = bytes(pkt[Raw])
        try:
            ascii_data = raw_data.decode("utf-8", errors="ignore")
        except:
            continue
        all_payloads.append(ascii_data)

# Save everything to a file (if you want to dig manually)
with open("payloads.txt", "w") as f:
    f.write("\n".join(all_payloads))

# Concatenate all text
full_data = "".join(all_payloads)

# Show only interesting parts
for keyword in ["flag", "FLAG", "ctf", "CTF", "{", "}", "da", "vinci"]:
    if keyword in full_data:
        print(f"[+] Found keyword '{keyword}' in stream!")

# Try Caesar shifts
for shift in [3, 7, 13, -3, -7, -13]:
    shifted = caesar(full_data, shift)
    if "flag{" in shifted.lower():
        print(f"[+] Caesar shift {shift} reveals: {shifted}")
