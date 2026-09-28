#!/usr/bin/env python3
"""fdrace2.log 분석.

fd 번호마다 "generation"(생성~close)을 추적한다.
  HIT      : DB 파일 generation의 fd에 opener가 아닌 thread가 I/O  -> fd 재사용 race 적중
  STALE    : 어떤 thread가 이전 generation(socket)에서 쓰던 fd로, 새 generation(파일)에 I/O
  EBADF    : 닫힌 fd에 I/O (race 직전까지 갔지만 아직 재사용 전이라 무해)
"""
import collections
import re
import sys

pat = re.compile(r"(\d+) (\w+)\s+tid=(\d+) fd=(-?\d+)\s*(.*)")
gen = {}          # fd -> dict(kind, tid, name, t, users)
hist = collections.defaultdict(list)  # fd -> previous generations
hits, stale, ebadf = [], [], []
counts = collections.Counter()

for line in open(sys.argv[1], errors="replace"):
    m = pat.match(line)
    if not m:
        continue
    t, k, tid, fd, rest = int(m[1]), m[2], int(m[3]), int(m[4]), m[5]
    counts[k] += 1
    if k in ("SOCKET", "ACCEPT", "OPEN", "DUP") and fd >= 0:
        if fd in gen:
            hist[fd].append(gen[fd])
        kind = "DB" if (k == "OPEN" and ".db" in rest) else ("FILE" if k == "OPEN" else k)
        gen[fd] = dict(kind=kind, tid=tid, name=rest.strip(), t=t, users={tid})
    elif k == "CLOSE":
        if fd in gen:
            g = gen.pop(fd)
            g["closed_by"], g["closed_t"] = tid, t
            hist[fd].append(g)
    elif k == "IO":
        g = gen.get(fd)
        if g is None:
            continue
        # sqlite는 pread64/pwrite64만 쓴다. DB fd에 read/write/recv/send가 오면 socket 코드(OpenSSL 등)가
        # 재사용된 fd 번호를 쓴 것이다 = race 적중.
        if g["kind"] == "DB" and not rest.endswith(("pread64", "pwrite64")):
            hits.append((t, tid, fd, rest, g))
        # 이 thread가 직전 generation(socket)의 사용자였고 현재 generation은 파일이면 stale
        if g["kind"] in ("DB", "FILE") and tid not in g["users"]:
            prev = hist[fd][-1] if hist[fd] else None
            if prev and tid in prev["users"] and prev["kind"] in ("SOCKET", "ACCEPT"):
                stale.append((t, tid, fd, rest, prev, g))
        g["users"].add(tid)
    elif k == "EBADF":
        ebadf.append((t, tid, fd, rest))

print("events:", dict(counts))
print(f"HIT (non-sqlite read/write on DB fd): {len(hits)}")
for t, tid, fd, sc, g in hits[:10]:
    print(f"  t={t} tid={tid} fd={fd} {sc}  DB opened by tid={g['tid']} {(t - g['t']) / 1e6:.3f}ms earlier")
print(f"STALE (old socket user touching new file generation): {len(stale)}")
for t, tid, fd, sc, prev, g in stale[:10]:
    print(f"  t={t} tid={tid} fd={fd} {sc}  prev={prev['kind']} closed_by={prev.get('closed_by')} "
          f"{(t - prev.get('closed_t', t)) / 1e6:.3f}ms after close; now {g['kind']} {g['name'][-40:]}")
print(f"EBADF (use of already-closed fd): {len(ebadf)}")
by = collections.Counter(sc for *_, sc in ebadf)
for sc, n in by.most_common():
    print(f"  {n:5d} {sc}")
