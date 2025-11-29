'''
from scapy.all import rdpcap, IP, TCP

packets = rdpcap("hard.pcap")

bits = []
for pkt in packets:
    if IP in pkt and TCP in pkt:
        # Example: extract LSB of the IP ID
        bits.append(str(pkt[IP].id & 1))

# Convert bitstream into bytes
message = ""
for i in range(0, len(bits), 8):
    byte = bits[i:i+8]
    if len(byte) == 8:
        message += chr(int("".join(byte), 2))

print(message)
'''

from scapy.all import rdpcap, IP, TCP

packets = rdpcap("hard.pcap")

def extract_bits(field):
    bits = []
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            if field == "ip_id":
                bits.append(pkt[IP].id & 1)
            elif field == "tcp_seq":
                bits.append(pkt[TCP].seq & 1)
            elif field == "ttl":
                bits.append(pkt[IP].ttl & 1)
    return bits

def bits_to_text(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            continue
        val = int("".join(str(b) for b in byte), 2)
        if 32 <= val <= 126 or val in (10, 13):  # printable ASCII + newline
            chars.append(chr(val))
        else:
            chars.append(".")
    return "".join(chars)

for field in ["ip_id", "tcp_seq", "ttl"]:
    bits = extract_bits(field)
    text = bits_to_text(bits)
    print(f"\n--- {field} ---")
    print(text[:200])