#!/usr/bin/env python3
"""표적 부하: 연결 A를 닫는 순간에 맞춰 B를 연결한다 (동시 연결 1개 = production 모양).

race 조건(관측): 닫는 thread가 WebSocket fd를 close 한 뒤 0.1~4ms 안에 receive thread가
같은 fd 번호로 read(). 그 사이 B의 accept socket 또는 DB open이 그 번호를 받으면 적중.
B 결과: S/N 정상, TIMEOUT(SSLRequest를 가로채임), 그 외 bytes(엉뚱한 데이터 수신)를 기록.
"""
import os, random, socket, struct, sys, time

PORT = int(os.environ.get("PORT", "15433"))
N = int(os.environ.get("N", "1000"))
SSLREQ = struct.pack("!II", 8, 80877103)
stats = {}


def open_conn():
    s = socket.socket(); s.settimeout(12)
    s.connect(("127.0.0.1", PORT)); s.sendall(SSLREQ)
    return s


def result(s):
    try:
        b = s.recv(64)
        return "S" if b == b"S" else ("N" if b == b"N" else ("EOF" if not b else "BYTES:" + b.hex()))
    except socket.timeout:
        return "TIMEOUT"
    except ConnectionResetError:
        return "RESET"


a = open_conn(); result(a)
for i in range(1, N + 1):
    # 서버 측 WebSocket 통신이 끝나 receive thread가 read에서 대기하도록 잠깐 둔다
    time.sleep(random.uniform(0.2, 0.6))
    delta = random.uniform(-0.002, 0.008)
    if delta < 0:
        b_sock = socket.socket(); b_sock.settimeout(12); b_sock.connect(("127.0.0.1", PORT))
        time.sleep(-delta); a.close()
    else:
        a.close(); time.sleep(delta)
        b_sock = socket.socket(); b_sock.settimeout(12); b_sock.connect(("127.0.0.1", PORT))
    t = time.monotonic(); b_sock.sendall(SSLREQ); r = result(b_sock); dt = time.monotonic() - t
    stats[r if not r.startswith("BYTES") else "BYTES"] = stats.get(r if not r.startswith("BYTES") else "BYTES", 0) + 1
    if r not in ("S", "N"):
        print(f"{time.strftime('%H:%M:%S', time.gmtime())} #{i} delta={delta*1000:+.2f}ms B={r} {dt:.3f}s  <<< ANOMALY", flush=True)
    elif i % 50 == 0:
        print(f"{time.strftime('%H:%M:%S', time.gmtime())} #{i} ok {stats}", flush=True)
    a = b_sock
a.close()
print("SUMMARY", stats, file=sys.stderr)
