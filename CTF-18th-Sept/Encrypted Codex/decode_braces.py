#!/usr/bin/env python3
# decode_braces.py
# Reads flag_candidates.txt, extracts { ... } substrings and tries common transforms.
# Writes promising outputs to braced_decode_results.txt and prints a concise summary.

import re, base64, sys
from collections import Counter

INFILE = "flag_candidates.txt"
OUTFILE = "braced_decode_results.txt"

# english-ish words to bias results
KEYWORDS = {"flag","ctf","leonardo","da","vinci","simplicity","ultimate","sophistication","learning","knowledge","study","art","science"}

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

def is_base64_like(s):
    s2 = s.strip()
    # require length >= 12 and only base64 chars + padding
    return len(s2) >= 12 and re.fullmatch(r"[A-Za-z0-9+/=]+\Z", s2) is not None

def pretty_print_hit(label, raw_bytes):
    try:
        txt = raw_bytes.decode('utf-8', errors='replace')
    except:
        txt = ''.join(chr(b) if 32<=b<127 else '.' for b in raw_bytes)
    # collapse newlines
    txt = txt.replace('\n', '\\n')
    return f"{label}: {txt}"

def score_text(txt):
    tl = txt.lower()
    score = 0
    for kw in KEYWORDS:
        if kw in tl:
            score += 10
    # count english-like words of length >=5
    words = re.findall(r"[A-Za-z]{5,}", txt)
    score += len(words)
    # prefer printable fraction
    if len(txt) > 0:
        pf = sum(1 for c in txt if 32 <= ord(c) < 127)/max(1,len(txt))
        if pf > 0.7:
            score += 2
    return score

def extract_braced(content):
    # find all occurrences of {...}
    return re.findall(r"\{([^}]*)\}", content, flags=re.DOTALL)

def try_transforms_on_token(token_bytes, token_text, out_fh, token_index):
    results = []
    # raw text check
    try:
        raw_text = token_bytes.decode('latin1')
    except:
        raw_text = ''.join(chr(b) if 32<=b<127 else '.' for b in token_bytes)
    s = raw_text
    scr = score_text(s)
    results.append(("RAW", s, scr))

    # Caesar on text (if token looks textual)
    if re.search(r"[A-Za-z]", raw_text):
        for shift in range(1,26):
            t = caesar_text(raw_text, shift)
            sc = score_text(t)
            if sc > 0:
                results.append((f"CAESAR+{shift}", t, sc))

    # try base64 if base64-like
    if is_base64_like(token_text):
        try:
            dec = base64.b64decode(token_text, validate=True)
            try:
                dec_txt = dec.decode('utf-8', errors='replace')
            except:
                dec_txt = dec.decode('latin1', errors='replace')
            sc = score_text(dec_txt)
            results.append(("BASE64", dec_txt, sc))
        except Exception:
            pass

    # operate on raw bytes: XOR keys
    for k in range(0,256):
        outb = single_byte_xor(token_bytes, k)
        try:
            outtxt = outb.decode('latin1')
        except:
            outtxt = ''.join(chr(b) if 32<=b<127 else '.' for b in outb)
        sc = score_text(outtxt)
        if sc >= 3:  # threshold to avoid huge output; tuned conservatively
            results.append((f"XOR_{k}", outtxt, sc))
        # XOR then ROTR7
        outb2 = rot_bytes(outb, 7, right=True)
        try:
            outtxt2 = outb2.decode('latin1')
        except:
            outtxt2 = ''.join(chr(b) if 32<=b<127 else '.' for b in outb2)
        sc2 = score_text(outtxt2)
        if sc2 >= 3:
            results.append((f"XOR_{k}_then_ROTR7", outtxt2, sc2))
        # ROTR7 then XOR
        outb3 = single_byte_xor(rot_bytes(token_bytes,7,right=True), k)
        try:
            outtxt3 = outb3.decode('latin1')
        except:
            outtxt3 = ''.join(chr(b) if 32<=b<127 else '.' for b in outb3)
        sc3 = score_text(outtxt3)
        if sc3 >= 3:
            results.append((f"ROTR7_then_XOR_{k}", outtxt3, sc3))

    # try pure ROTR 1..7
    for r in range(1,8):
        outb = rot_bytes(token_bytes, r, right=True)
        try:
            outtxt = outb.decode('latin1')
        except:
            outtxt = ''.join(chr(b) if 32<=b<127 else '.' for b in outb)
        sc = score_text(outtxt)
        if sc >= 3:
            results.append((f"ROTR{r}", outtxt, sc))

    # sort results by score desc and write top ones
    results_sorted = sorted(results, key=lambda x: x[2], reverse=True)
    if results_sorted:
        out_fh.write(f"=== Token #{token_index} (original: {{{token_text}}}) ===\n")
        for label, txt, sc in results_sorted[:40]:  # write top 40 per token
            out_fh.write(f"{label} (score={sc}):\n{txt}\n\n")
        out_fh.write("\n\n")
    return results_sorted

def main():
    try:
        raw = open(INFILE, "r", encoding="utf-8", errors="ignore").read()
    except FileNotFoundError:
        print(f"{INFILE} not found. Make sure your candidate file is named {INFILE}.")
        return

    tokens = extract_braced(raw)
    tokens = [t.strip() for t in tokens if t.strip()]
    print(f"Found {len(tokens)} braced tokens. Trying transforms on each (may take a bit).")
    if not tokens:
        print("No { } tokens found in file.")
        return

    with open(OUTFILE, "w", encoding="utf-8") as out_fh:
        overall_hits = []
        for i, tok in enumerate(tokens):
            # token text and bytes
            tok_text = tok
            tok_bytes = tok_text.encode('latin1', errors='ignore')
            res = try_transforms_on_token(tok_bytes, tok_text, out_fh, i)
            if res:
                # record top hit
                overall_hits.append((i, res[0]))
        print(f"Done. Results written to {OUTFILE}")

        # Print concise summary of best hits
        print("\nTop hits summary:")
        for i, (label, txt, sc) in overall_hits[:20]:
            oneline = txt.replace("\n","\\n")[:200]
            print(f"Token#{i} best {label} score={sc}: {oneline}")

if __name__ == "__main__":
    main()
