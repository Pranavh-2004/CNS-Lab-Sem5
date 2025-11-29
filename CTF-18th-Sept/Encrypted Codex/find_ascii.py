import os, re

OUT_DIR = "/Users/pranavhemanth/Code/Academics/CNS-S5/CTF-18th-Sept/Encrypted Codex/decode_outputs"

ascii_run = re.compile(rb"[ -~]{6,}")  # printable ASCII runs of length 6+

for fname in os.listdir(OUT_DIR):
    if not fname.endswith(".bin"):
        continue
    path = os.path.join(OUT_DIR, fname)
    with open(path, "rb") as f:
        data = f.read()
    matches = ascii_run.findall(data)
    if matches:
        print(f"\n[+] {fname} -> found {len(matches)} ascii sequences")
        for m in matches[:20]:  # print only first 20 hits
            print("   ", m.decode(errors="ignore"))
