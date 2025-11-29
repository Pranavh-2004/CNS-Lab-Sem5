#!/usr/bin/env python3
# decode_lisa_trailer.py
# Usage: python3 decode_lisa_trailer.py
#
# What it does:
# 1. Parse a raw-linktype pcap (linktype 228) to reassemble TCP streams.
# 2. Find the PNG in the HTTP response stream and locate IEND.
# 3. Extract trailer bytes after IEND.
# 4. Try transforms (xor/add/sub with several keys, rotate-right-by-7, byte rotations, combinations).
# 5. Save candidate plaintexts (and the transformed trailer blobs) when they look printable or contain keywords.

import os, struct, socket, json, binascii
from collections import defaultdict

PCAP = "Lisa.pcap"   # change if filename differs
OUT_DIR = "decode_outputs"
os.makedirs(OUT_DIR, exist_ok=True)

def read_pcap_packets(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise RuntimeError("Not a pcap or truncated header")
        magic = struct.unpack('<I', gh[:4])[0]
        endian = '<' if magic in (0xa1b2c3d4, 0xd4c3b2a1) else '>'
        _, _, _, _, _, network = struct.unpack(endian + 'HHiiii', gh[4:24])
        packets = []
        while True:
            hdr = f.read(16)
            if not hdr or len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            packets.append((ts_sec + ts_usec/1e6, data))
    return packets, network

def parse_ipv4_and_tcp(frame, network):
    # network 228 -> raw IPv4 packet; else expect Ethernet frame
    if network == 228:
        ip = frame
    else:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack('!H', frame[12:14])[0]
        if ethertype != 0x0800:
            return None
        ip = frame[14:]
    if len(ip) < 20:
        return None
    ver_ihl = ip[0]
    ihl = (ver_ihl & 0x0F) * 4
    proto = ip[9]
    if proto != 6:
        return None
    src = socket.inet_ntoa(ip[12:16])
    dst = socket.inet_ntoa(ip[16:20])
    tcp = ip[ihl:]
    if len(tcp) < 20:
        return None
    sport = struct.unpack('!H', tcp[0:2])[0]
    dport = struct.unpack('!H', tcp[2:4])[0]
    seq = struct.unpack('!I', tcp[4:8])[0]
    data_offset = (tcp[12] >> 4) * 4
    payload = tcp[data_offset:]
    return {'src':src, 'dst':dst, 'sport':sport, 'dport':dport, 'seq':seq, 'payload':payload}

def reassemble_tcp_streams(pcap_path):
    pkts, network = read_pcap_packets(pcap_path)
    streams = defaultdict(list)
    for ts, frame in pkts:
        parsed = parse_ipv4_and_tcp(frame, network)
        if not parsed: continue
        if len(parsed['payload']) == 0: continue
        key = (parsed['src'], parsed['dst'], parsed['sport'], parsed['dport'])
        streams[key].append((parsed['seq'], parsed['payload']))
    # join segments by sequence number order (simple reassembly)
    reassembled = {}
    for k, segs in streams.items():
        segs_sorted = sorted(segs, key=lambda x: x[0])
        data = b''.join([p for s,p in segs_sorted])
        reassembled[k] = data
    return reassembled

def find_png_and_trailer(data_bytes):
    sig = b'\x89PNG\r\n\x1a\n'
    idx = data_bytes.find(sig)
    if idx == -1:
        return None, None, None
    png = data_bytes[idx:]
    # find IEND chunk (pattern: 00 00 00 00 49 45 4E 44)
    iend_pat = b'\x00\x00\x00\x00IEND'
    iend_idx = png.find(iend_pat)
    if iend_idx == -1:
        return png, None, None
    # end of IEND chunk = iend_idx + length(4)+type(4)+crc(4) = iend_idx + 12
    end_iend = iend_idx + 12
    clean_png = png[:end_iend]
    trailer = png[end_iend:]
    return clean_png, trailer, end_iend

# byte utility transforms
def rotr_byte(b, n): return ((b >> n) | ((b << (8-n)) & 0xFF)) & 0xFF
def rotl_byte(b, n): return ((b << n) & 0xFF) | (b >> (8-n))

def printable_fraction(bts):
    if not bts: return 0.0
    p = sum(1 for b in bts if 32 <= b < 127 or b in (9,10,13))
    return p / len(bts)

def looks_promising(bts):
    # criteria for saving / printing result:
    # - contains 'flag' or 'leonardo' or contains '}' or printable fraction > 0.6
    s = bts.lower()
    if b'flag' in s or b'leonardo' in s or b'}' in s: 
        return True
    if printable_fraction(bts) > 0.60:
        return True
    return False

def try_transforms(trailer, outdir):
    keys = [3,4,7,13]   # candidate keys per clues
    results = []
    sample = trailer[:2000]
    # Try: raw XOR / add / sub with each key
    for k in keys:
        # xor
        out_xor = bytes([b ^ k for b in trailer])
        if looks_promising(out_xor[:2000]):
            fname = os.path.join(outdir, f"trailer_xor_{k}.bin")
            open(fname, "wb").write(out_xor)
            print(f"[+] XOR with {k} looks promising -> wrote {fname} (printable_frac={printable_fraction(out_xor):.3f})")
            results.append(("xor",k,fname))
        # add/sub (try both directions)
        out_add = bytes([(b + k) & 0xFF for b in trailer])
        out_sub = bytes([(b - k) & 0xFF for b in trailer])
        if looks_promising(out_add[:2000]):
            fname = os.path.join(outdir, f"trailer_add_{k}.bin")
            open(fname, "wb").write(out_add)
            print(f"[+] ADD {k} looks promising -> wrote {fname} (pf={printable_fraction(out_add):.3f})")
            results.append(("add",k,fname))
        if looks_promising(out_sub[:2000]):
            fname = os.path.join(outdir, f"trailer_sub_{k}.bin")
            open(fname, "wb").write(out_sub)
            print(f"[+] SUB {k} looks promising -> wrote {fname} (pf={printable_fraction(out_sub):.3f})")
            results.append(("sub",k,fname))

    # Try single-byte rotations (rotate-right by 7 as clue): rotr by 7 is same as rotl by 1
    # We'll try rotr by 7 and rotl by 7, and rotr by 1..7 generally.
    for n in range(1,8):
        out_rotr = bytes([rotr_byte(b, n) for b in trailer])
        if looks_promising(out_rotr[:2000]):
            fname = os.path.join(outdir, f"trailer_rotr_{n}.bin")
            open(fname, "wb").write(out_rotr)
            print(f"[+] ROTR {n} looks promising -> wrote {fname} (pf={printable_fraction(out_rotr):.3f})")
            results.append(("rotr",n,fname))
        out_rotl = bytes([rotl_byte(b, n) for b in trailer])
        if looks_promising(out_rotl[:2000]):
            fname = os.path.join(outdir, f"trailer_rotl_{n}.bin")
            open(fname, "wb").write(out_rotl)
            print(f"[+] ROTL {n} looks promising -> wrote {fname} (pf={printable_fraction(out_rotl):.3f})")
            results.append(("rotl",n,fname))

    # Try combining: rotr by 7 then xor with keys, and xor then rotr by 7 (both orders)
    for k in keys:
        rotr7_then_xor = bytes([rotr_byte(b,7) ^ k for b in trailer])
        xor_then_rotr7 = bytes([rotr_byte(b ^ k, 7) for b in trailer])
        if looks_promising(rotr7_then_xor[:2000]):
            fname = os.path.join(outdir, f"trailer_rotr7_xor_{k}.bin")
            open(fname, "wb").write(rotr7_then_xor)
            print(f"[+] ROTR7 then XOR {k} -> {fname} (pf={printable_fraction(rotr7_then_xor):.3f})")
            results.append(("rotr7_xor",k,fname))
        if looks_promising(xor_then_rotr7[:2000]):
            fname = os.path.join(outdir, f"trailer_xor_{k}_rotr7.bin")
            open(fname, "wb").write(xor_then_rotr7)
            print(f"[+] XOR {k} then ROTR7 -> {fname} (pf={printable_fraction(xor_then_rotr7):.3f})")
            results.append(("xor_rotr7",k,fname))

    # Also try brute XOR single-byte keys 0..255 (fast) but only keep promising
    for k in range(256):
        out = bytes([b ^ k for b in sample])
        if printable_fraction(out) > 0.75 or b'flag' in out.lower() or b'leonardo' in out.lower():
            # write whole trailer XORed by k to file for full inspection
            fname = os.path.join(outdir, f"trailer_xor_full_{k}.bin")
            open(fname, "wb").write(bytes([b ^ k for b in trailer]))
            print(f"[+] full XOR with {k} produced promising sample -> saved {fname} (sample_pf={printable_fraction(out):.3f})")
            results.append(("xor_full",k,fname))
    if not results:
        print("No promising transforms found by automated heuristics. Try inspecting raw trailer or changing heuristics.")
    return results

def dump_preview(bts, label, maxlen=512):
    txt = ''.join([chr(b) if 32<=b<127 or b in (9,10,13) else '.' for b in bts[:maxlen]])
    print(f"--- Preview: {label} ---")
    print(txt)
    print("--- end preview ---\n")

def main():
    print("[*] Reassembling TCP streams from", PCAP)
    streams = reassemble_tcp_streams(PCAP)
    print(f"[*] Found {len(streams)} TCP streams.")
    # try to find the stream that contains PNG signature
    found = False
    for k, data in streams.items():
        if b'\x89PNG\r\n\x1a\n' in data:
            print("[*] PNG found in stream:", k)
            clean_png, trailer, endoffset = find_png_and_trailer(data)
            if clean_png:
                png_path = os.path.join(OUT_DIR, "Lisa_extracted.png")
                open(png_path, "wb").write(clean_png)
                print("[+] Wrote PNG (clean up to IEND) ->", png_path, "len", len(clean_png))
            if trailer is None:
                print("[!] No trailer found after IEND in this stream.")
                return
            print("[*] Trailer size (bytes):", len(trailer))
            # save raw trailer
            raw_path = os.path.join(OUT_DIR, "trailer_raw.bin")
            open(raw_path, "wb").write(trailer)
            print("[+] Wrote raw trailer to", raw_path)
            dump_preview(trailer, "raw_trailer (hex-as-ascii preview)")
            # try the suite of transforms
            results = try_transforms(trailer, OUT_DIR)
            # print previews of any saved candidate files
            for typ, key, fname in results:
                content = open(fname, "rb").read()
                dump_preview(content, f"{typ} {key} preview")
            found = True
            break
    if not found:
        print("[-] No PNG found in any reassembled stream. Try increasing reassembly logic or check pcap linktype.")

if __name__ == "__main__":
    main()
