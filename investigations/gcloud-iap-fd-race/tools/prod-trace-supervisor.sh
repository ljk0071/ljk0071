#!/usr/bin/env bash
# production IAP gcloud에 prod-fdrace.bt를 계속 붙여 두고, default_configs.db 손상 시 증거를 자동 보존한다.
# 서비스/프로세스/DB는 읽기만 한다. (복구는 하지 않음)
set -u
BASE=/var/oled/diary-forensics/prod-trace
BT=$BASE/prod-fdrace.bt
SVC=diary-db-iap-tunnel.service
DB=/home/opc/.config/gcloud-diary-iap/default_configs.db
TS_LOG=/var/oled/diary-forensics/iap-timestamp/stderr-timestamped.log
MAX_BYTES=$((300 * 1024 * 1024))
cur_pid=""; bt_pid=""; log=""; last_state=ok; n=0

start_tracer() {
  log=$BASE/fdrace-pid$1-$(date -u +%Y%m%dT%H%M%SZ).log
  sudo setsid bpftrace "$BT" "$1" > "$log" 2>&1 < /dev/null &
  bt_pid=$!
  echo "$(date -u +%FT%TZ) tracer started for gcloud pid=$1 log=$log" >> $BASE/supervisor.log
}
stop_tracer() { [ -n "$bt_pid" ] && sudo pkill -INT -P "$bt_pid" 2>/dev/null; sudo kill -INT "$bt_pid" 2>/dev/null; bt_pid=""; }
db_state() {
  python3 - "$DB" <<'PY' 2>/dev/null || echo error
import sqlite3, sys
try: print("ok" if sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True).execute("pragma integrity_check").fetchone()[0] == "ok" else "corrupt")
except Exception: print("corrupt")
PY
}

trap 'stop_tracer; exit 0' INT TERM
last_state=$(db_state); echo "$(date -u +%FT%TZ) supervisor started, initial db state=$last_state" >> $BASE/supervisor.log
while true; do
  pid=$(systemctl --user show "$SVC" -p MainPID --value)
  if [ "$pid" != "$cur_pid" ] || ! sudo kill -0 "${bt_pid:-0}" 2>/dev/null || [ "$(stat -c %s "$log" 2>/dev/null || echo 0)" -gt $MAX_BYTES ]; then
    stop_tracer; cur_pid=$pid
    [ "$pid" != 0 ] && start_tracer "$pid"
    ls -1t $BASE/fdrace-pid*.log 2>/dev/null | tail -n +6 | xargs -r rm -f   # 최근 5개만 유지
  fi
  n=$((n + 1))
  if [ $((n % 6)) = 0 ]; then
    s=$(db_state)
    if [ "$s" != ok ] && [ "$last_state" = ok ]; then
      E=/var/oled/diary-forensics/prod-corruption-$(date -u +%Y%m%dT%H%M%SZ); mkdir -p $E
      cp -a "$DB" $E/default_configs.db.corrupt; stat "$DB" > $E/db-stat.txt
      cp -a "$log" $E/fdrace.log; ls -1t $BASE/fdrace-pid*.log | sed -n 2p | xargs -r -I{} cp -a {} $E/fdrace-prev.log
      tail -n 20000 $TS_LOG > $E/iap-stderr-tail.log
      echo "$(date -u +%FT%TZ) CORRUPTION detected (state=$s) evidence=$E" >> $BASE/supervisor.log
    fi
    last_state=$s
  fi
  sleep 5
done
