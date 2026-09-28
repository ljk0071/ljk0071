#!/usr/bin/env bash
# 격리 재현: 복사한 CLOUDSDK_CONFIG로 :15433 gcloud tunnel + fdrace.bt + 부하.
# production(diary-db-iap-tunnel.service / :15432 / 기존 config)은 건드리지 않는다.
# usage: run.sh start | load TOTAL CONC | check | stop
set -uo pipefail

R="$(cat /var/oled/diary-forensics/repro-current)"
CONFIG="$R/config"
PORT=15433
GCLOUD=/home/opc/google-cloud-sdk/bin/gcloud

gcloud_pid() { pgrep -f "start-iap-tunnel diary-db 5432 --local-host-port=127.0.0.1:${PORT}" | head -1; }

check_dbs() {
  for db in "$CONFIG"/*.db; do
    [ -e "$db" ] || continue
    r=$(python3 - "$db" <<'PY'
import sqlite3, sys
try:
    c = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    print(c.execute("pragma integrity_check").fetchone()[0])
except Exception as e:
    print(repr(e))
PY
)
    printf '%s %s size=%s sha=%s hdr29=%s\n' "$(basename "$db")" "$r" "$(stat -c %s "$db")" \
      "$(sha256sum "$db" | cut -c1-16)" "$(xxd -s 29 -l 5 -p "$db")"
  done
}

case "${1:-}" in
start)
  if ss -lnt | grep -q ":${PORT} "; then echo "port $PORT busy"; exit 1; fi
  # stderr는 pipe로 보낸다: gcloud의 stderr write가 regular-file write로 잡히지 않게.
  # 파일 로깅도 끈다. 그러면 gcloud의 regular-file write는 sqlite(+이상 write)만 남는다.
  CLOUDSDK_CONFIG="$CONFIG" CLOUDSDK_CORE_DISABLE_FILE_LOGGING=true \
  setsid nohup "$GCLOUD" compute start-iap-tunnel diary-db 5432 \
    --local-host-port=127.0.0.1:${PORT} \
    --project=<PROJECT> --zone=us-west1-b --verbosity=debug \
    2> >(while IFS= read -r l; do printf '%s %s\n' "$(date -u +%H:%M:%S.%3N)" "$l"; done > "$R/gcloud-stderr.log") \
    > "$R/gcloud-stdout.log" < /dev/null &
  for i in $(seq 1 30); do ss -lnt | grep -q ":${PORT} " && break; sleep 1; done
  P=$(gcloud_pid); echo "gcloud pid=$P"; echo "$P" > "$R/gcloud.pid"
  [ -n "$P" ] || { echo "gcloud failed to start"; tail -20 "$R/gcloud-stderr.log"; exit 1; }
  sudo setsid nohup bpftrace "$R/fdrace.bt" "$P" > "$R/fdrace.log" 2>&1 < /dev/null &
  for i in $(seq 1 60); do grep -q "tracer started" "$R/fdrace.log" 2>/dev/null && break; sleep 1; done
  echo "bpftrace: $(head -2 "$R/fdrace.log" | tr '\n' ' ')"
  check_dbs
  ;;
load)
  PORT=$PORT TOTAL="${2:-300}" CONC="${3:-6}" python3 "$R/load.py" >> "$R/load.log" 2>> "$R/load-summary.log"
  tail -1 "$R/load-summary.log"
  ;;
check)
  P=$(cat "$R/gcloud.pid"); echo "gcloud pid=$P alive=$(kill -0 "$P" 2>/dev/null && echo yes || echo no) fds=$(sudo ls /proc/$P/fd 2>/dev/null | wc -l)"
  check_dbs
  echo "fdrace lines=$(wc -l < "$R/fdrace.log") TLS-file-writes=$(grep -c 'TLS-LOOKING' "$R/fdrace.log") 5B-file-reads=$(grep -c '5-BYTE READ' "$R/fdrace.log")"
  echo "gcloud SSL errors: $(grep -cE 'SSLError|UNEXPECTED_MESSAGE|WRONG_VERSION|RECORD_LAYER|malformed' "$R/gcloud-stderr.log")"
  ;;
stop)
  P=$(cat "$R/gcloud.pid" 2>/dev/null)
  [ -n "$P" ] && kill "$P" 2>/dev/null
  sudo pkill -INT -f "bpftrace $R/fdrace.bt"
  sleep 2; echo "stopped (gcloud $P)"
  ;;
*) echo "usage: $0 start|load TOTAL CONC|check|stop"; exit 2 ;;
esac
