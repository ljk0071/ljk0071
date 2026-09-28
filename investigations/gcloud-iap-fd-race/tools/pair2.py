#!/usr/bin/env python3
"""pgjdbc/Hikari 연결 교체 모양의 표적 부하.

A: SSLRequest -> 'S' -> PostgreSQL TLS handshake -> Terminate('X') 전송 -> 즉시 raw socket close
B: A를 닫는 순간에 맞춰 연결 (Hikari는 retire 직후 대체 연결을 연다)
socket이 닫힌 뒤에도 서버 쪽 frame(PG close_notify, WebSocket close)이 여러 개 도착하므로
receive thread가 두 번째 read()를 재사용된 fd 번호로 호출할 수 있다.
"""
import os, random, socket, ssl, struct, sys, time

PORT = int(os.environ.get("PORT", "15433"))
N = int(os.environ.get("N", "1000"))
SSLREQ = struct.pack("!II", 8, 80877103)
TERMINATE = b"X\x00\x00\x00\x04"
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
stats = {}


def tls_conn():
    raw = socket.socket(); raw.settimeout(12); raw.connect(("127.0.0.1", PORT)); raw.sendall(SSLREQ)
    if raw.recv(1) != b"S":
        raise RuntimeError("no S")
    return raw, ctx.wrap_socket(raw, server_hostname="diary-db")


def probe(s):
    s.sendall(SSLREQ)
    try:
        b = s.recv(64)
        return "S" if b == b"S" else ("EOF" if not b else "BYTES:" + b.hex())
    except socket.timeout:
        return "TIMEOUT"
    except ConnectionResetError:
        return "RESET"


for i in range(1, N + 1):
    try:
        raw, tls = tls_conn()
    except Exception as e:  # noqa: BLE001
        stats["A_FAIL"] = stats.get("A_FAIL", 0) + 1
        print(f"{time.strftime('%H:%M:%S', time.gmtime())} #{i} A setup failed {e!r}  <<< ANOMALY", flush=True)
        continue
    time.sleep(random.uniform(0.05, 0.4))
    tls.sendall(TERMINATE)
    delta = random.uniform(-0.002, 0.010)
    if delta < 0:
        b = socket.socket(); b.settimeout(12); b.connect(("127.0.0.1", PORT)); time.sleep(-delta); raw.close()
    else:
        raw.close(); time.sleep(delta); b = socket.socket(); b.settimeout(12); b.connect(("127.0.0.1", PORT))
    r = probe(b); b.close()
    k = r if not r.startswith("BYTES") else "BYTES"; stats[k] = stats.get(k, 0) + 1
    if r != "S":
        print(f"{time.strftime('%H:%M:%S', time.gmtime())} #{i} delta={delta*1000:+.2f}ms B={r}  <<< ANOMALY", flush=True)
    elif i % 50 == 0:
        print(f"{time.strftime('%H:%M:%S', time.gmtime())} #{i} ok {stats}", flush=True)
print("SUMMARY", stats, file=sys.stderr)
