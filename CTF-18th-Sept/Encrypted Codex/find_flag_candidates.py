#!/usr/bin/env python3
# find_flag_candidates.py
# Reads payloads.txt, finds long printable runs and tries many transforms to reveal flags.
# Output: prints promising candidates and writes them to flag_candidates.txt

import re, base64, sys
from collections import Counter

INPUT = "payloads.txt"
OUT = "flag_candidates.txt"

PRINTABLE_RUN_RE = re.compile(rb"[ -~]{20,}")  # runs of printable ascii >= 20 chars
BASE64_RE = re.compile(rb"^[A-Za-z0-9+/=]{16,}$")

def rotl_byte(b, n): return ((b << n) & 0xFF) | (b >> (8-n))
def rotr_byte(b, n): return (b >> n) | ((b << (8-n)) & 0xFF)

def caesar_text(s, shift):
    out = []
    for ch in s:
        if 'a' <= ch <= 'z':
            out.append(chr((ord(ch)-97+shift) % 26 + 97))
        elif 'A' <= ch <= 'Z':
            out.append(chr((ord(ch)-65+shift) % 26 + 65))
        else:
            out.append(ch)
    return ''.join(out)

def single_byte_xor(bs, k):
    return bytes([b ^ k for b in bs])

def rot_bytes(bs, n, right=True):
    if right:
        return bytes([rotr_byte(b, n) for b in bs])
    else:
        return bytes([rotl_byte(b, n) for b in bs])

def looks_promising_text(s):
    sl = s.lower()
    if "flag{" in sl or "ctf{" in sl or "leonardo" in sl or "da vinci" in sl:
        return True
    # also if contains braces
    if "{" in s and "}" in s:
        return True
    # or contains a long english-like token (letters + space)
    words = re.findall(r"[A-Za-z]{6,}", s)
    if len(words) >= 3:
        return True
    return False

def try_base64_guess(bs):
    try:
        decoded = base64.b64decode(bs, validate=True)
        # treat as text if many printable chars
        if sum(1 for b in decoded if 32 <= b < 127) / max(1, len(decoded)) > 0.6:
            return decoded.decode('latin1', errors='replace')
    except Exception:
        return None
    return None

def scan_and_try():
    with open(INPUT, "rb") as f:
        data = f.read()

    runs = PRINTABLE_RUN_RE.findall(data)
    # deduplicate and sort by length desc
    runs_unique = sorted({r for r in runs}, key=len, reverse=True)

    print(f"Found {len(runs_unique)} printable runs >=20 chars. Trying top 200 runs.")
    runs_unique = runs_unique[:200]

    results = []
    seen_strings = set()

    for i, run in enumerate(runs_unique):
        # work with bytes and text views
        try:
            text = run.decode('latin1')
        except:
            text = ''.join(chr(b) if 32<=b<127 else '.' for b in run)

        # quick check on raw
        if looks_promising_text(text):
            snippet = text[:400]
            label = f"RAW-run#{i}"
            if snippet not in seen_strings:
                results.append((label, snippet))
                seen_strings.add(snippet)

        # try Caesar shifts on ascii-like text
        if re.search(r"[A-Za-z]", text):
            lowtext = text
            for shift in range(1,26):
                cand = caesar_text(lowtext, shift)
                if looks_promising_text(cand):
                    label = f"CAESAR+{shift}-run#{i}"
                    snippet = cand[:400]
                    if snippet not in seen_strings:
                        results.append((label, snippet)); seen_strings.add(snippet)

        # try base64 if run looks like base64 or contains = at end
        # also try splitting run into whitespace-separated tokens and test each token
        tokens = re.split(r"\s+", run.decode('latin1', errors='ignore'))
        for tok in tokens:
            tbs = tok.encode('latin1', errors='ignore')
            if len(tbs) >= 16 and BASE64_RE.match(tbs):
                dec = try_base64_guess(tbs)
                if dec and looks_promising_text(dec):
                    label = f"BASE64-decode-run#{i}"
                    snippet = dec[:500]
                    if snippet not in seen_strings:
                        results.append((label,snippet)); seen_strings.add(snippet)

        # Try single-byte XOR (+/-) across sample (only on bytes)
        sample = run
        for k in range(256):
            out = single_byte_xor(sample, k)
            try:
                s_out = out.decode('latin1', errors='replace')
            except:
                s_out = ''.join(chr(b) if 32<=b<127 else '.' for b in out)
            if looks_promising_text(s_out):
                label = f"XOR_{k}-run#{i}"
                snippet = s_out[:500]
                if snippet not in seen_strings:
                    results.append((label,snippet)); seen_strings.add(snippet)

            # try XOR then ROTR7 (hint)
            out2 = rot_bytes(out, 7, right=True)
            s_out2 = out2.decode('latin1', errors='replace')
            if looks_promising_text(s_out2):
                label = f"XOR_{k}_then_ROTR7-run#{i}"
                snippet = s_out2[:500]
                if snippet not in seen_strings:
                    results.append((label,snippet)); seen_strings.add(snippet)

            # try ROTR7 then XOR
            out3 = single_byte_xor(rot_bytes(sample,7,right=True), k)
            s_out3 = out3.decode('latin1', errors='replace')
            if looks_promising_text(s_out3):
                label = f"ROTR7_then_XOR_{k}-run#{i}"
                snippet = s_out3[:500]
                if snippet not in seen_strings:
                    results.append((label,snippet)); seen_strings.add(snippet)

        # Try rotating bytes alone (1..7)
        for r in range(1,8):
            out = rot_bytes(sample, r, right=True)
            s_out = out.decode('latin1', errors='replace')
            if looks_promising_text(s_out):
                label = f"ROTR{r}-run#{i}"
                snippet = s_out[:500]
                if snippet not in seen_strings:
                    results.append((label,snippet)); seen_strings.add(snippet)

    # Write results to file and print concise summary
    if not results:
        print("No promising candidates found with current heuristics.")
        return

    with open(OUT, "w", encoding="utf-8") as fo:
        for label, snippet in results:
            fo.write(f"=== {label} ===\n")
            fo.write(snippet + "\n\n")

    print(f"Wrote {len(results)} candidate snippets to {OUT}. Showing them now (trimmed):\n")
    for label, snippet in results:
        print(f"--- {label} ---")
        print(snippet[:400].replace("\n","\\n"))
        print()
    print("Done. Inspect file:", OUT)

if __name__ == "__main__":
    scan_and_try()
