#!/usr/bin/env bash
# 적중(손상/TLS 파일 write/DB fd에 대한 비-sqlite I/O)까지 500개 단위로 부하 반복.
R="$(cat /var/oled/diary-forensics/repro-current)"; cd "$R"
ROUNDS="${1:-12}"; CONC="${2:-3}"; GAP="${3:-0.3}"
for r in $(seq 1 "$ROUNDS"); do
  PORT=15433 TOTAL=500 CONC=$CONC GAP_MAX=$GAP python3 load.py >> load.log 2>> load-summary.log
  bad=$(./run.sh check | grep '\.db ' | grep -vc ' ok ')
  a=$(python3 analyze.py fdrace3.log)
  hit=$(echo "$a" | sed -n 's/^HIT[^:]*: //p'); raw=$(grep -c 'RAW-FD USE-AFTER-CLOSE' fdrace3.log); tls=$(grep -c 'TLS-LOOKING' fdrace3.log)
  echo "$(date -u +%H:%M:%S) round=$r corrupt_dbs=$bad hit=$hit raw_uaf=$raw tls_file_writes=$tls $(tail -1 load-summary.log)" | tee -a hunt.log
  if [ "$bad" != 0 ] || [ "$hit" != 0 ] || [ "$tls" != 0 ]; then echo "!!! REPRODUCED in round $r" | tee -a hunt.log; ./run.sh check | tee -a hunt.log; exit 0; fi
done
echo "no reproduction after $ROUNDS rounds" | tee -a hunt.log
