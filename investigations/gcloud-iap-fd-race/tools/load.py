#!/usr/bin/env python3
"""Short-lived PostgreSQL SSLRequest connections against the repro IAP tunnel.

Patterns (mixed, to hit different close orderings inside gcloud):
  full   : connect -> SSLRequest -> recv(1) -> close
  abrupt : connect -> SSLRequest -> close immediately (local EOF while WebSocket is connecting)
  rst    : connect -> SSLRequest -> recv(1) -> close with SO_LINGER 0 (RST)
"""
import os
import random
import socket
import struct
import sys
import threading
import time

PORT = int(os.environ.get("PORT", "15433"))
TOTAL = int(os.environ.get("TOTAL", "300"))
CONC = int(os.environ.get("CONC", "6"))
SSLREQ = struct.pack("!II", 8, 80877103)

lock = threading.Lock()
counter = {"n": 0}
stats = {}


def one(i):
    kind = random.choice(["full", "full", "abrupt", "rst"])
    s = socket.socket()
    s.settimeout(10)
    t = time.monotonic()
    try:
        s.connect(("127.0.0.1", PORT))
        s.sendall(SSLREQ)
        if kind == "abrupt":
            time.sleep(random.uniform(0, 0.5))
            res = "SENT"
        else:
            r = s.recv(1)
            res = r.decode(errors="replace") if r else "EOF"
            if kind == "rst":
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except socket.timeout:
        res = "TIMEOUT"
    except ConnectionResetError:
        res = "RESET"
    except Exception as e:  # noqa: BLE001
        res = type(e).__name__
    finally:
        s.close()
    dt = time.monotonic() - t
    with lock:
        stats[(kind, res)] = stats.get((kind, res), 0) + 1
    print(f"{time.strftime('%H:%M:%S', time.gmtime())} #{i} {kind} {res} {dt:.3f}s", flush=True)


GAP_MAX = float(os.environ.get("GAP_MAX", "0"))


def worker():
    while True:
        if GAP_MAX:
            # 순차 패턴: 직전 연결 종료 후 0~GAP_MAX초 뒤 다음 연결 (05:44 [518]->[519] 모양)
            time.sleep(random.uniform(0, GAP_MAX))
        with lock:
            if counter["n"] >= TOTAL:
                return
            counter["n"] += 1
            i = counter["n"]
        one(i)


threads = [threading.Thread(target=worker) for _ in range(CONC)]
for th in threads:
    th.start()
for th in threads:
    th.join()
print("SUMMARY", sorted(stats.items()), file=sys.stderr)
