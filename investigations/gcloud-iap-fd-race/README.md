# gcloud IAP tunnel fd use-after-close 추적기 — 원본

[`../gcloud-iap-fd-race.html`](https://ljk0071.github.io/ljk0071/investigations/gcloud-iap-fd-race.html) 리포트를 만드는 원본과, 조사에 실제로 쓴 도구다.

## 다시 빌드하기

```bash
python3 build.py
```

- `template.html`의 `<!--E:이름-->` 자리에 `evidence/`의 발췌를 넣어 `../gcloud-iap-fd-race.html`을 새로 쓴다.
- 빌드할 때 가림 규칙을 한 번 더 적용하고, 끝에 가림 검사를 한다. 검사에 걸리면 종료 코드 1을 낸다.
- 외부 의존성은 없다. Python 3 표준 라이브러리만 쓴다.

## 구성

| 경로 | 내용 |
|---|---|
| `template.html` | 리포트 본문과 스타일, 인터랙션 스크립트 |
| `build.py` | 증거를 넣고 가림 검사하는 빌드 스크립트 |
| `evidence/` | 증거 발췌 (가림 처리 완료, 아래 표) |
| `tools/` | 조사에 쓴 bpftrace 프로그램과 부하·분석 스크립트 |

### evidence/

| 파일 | 리포트 위치 | 내용 |
|---|---|---|
| `ab-test.txt` | E1 | 장애 중 A/B 진단 결과 (기존 tunnel, 새 tunnel) |
| `corruption-0924.txt` | E2 | 09-24 05:44 손상 전후 gcloud 로그와 시간당 줄 수 |
| `corruption-0925-window.txt` | E3 | 09-25 10:32 손상 전후 gcloud 로그 (리포트에는 앞 32줄) |
| `trace-excerpt.txt` | E4, 타임라인 | 확증 사건(09-26 19:31)의 bpftrace 발췌. 타임라인 차트가 이 원문을 파싱함 |
| `gcloud-log-excerpt.txt` | E5 | 확증 사건의 gcloud 로그와 손상 DB 헤더 |
| `near-miss.txt` | E6 | production near-miss (리포트에는 fd 7 관련 줄만) |
| `lab-stats.txt` | E7 | 실험실 재현 통계 |
| `db-hex.txt` | E8, Hex 뷰어 | 손상 DB 4개의 hexdump |
| `gcloud-errors.txt` | E9 | gcloud stderr의 TLS 오류 누적 |
| `source-excerpts.txt` | 코드 경로 | Google Cloud SDK 582.0.0 발췌 (Apache License 2.0), 옛 eBPF 필터와 `s_dev` 실측 |

### tools/

| 파일 | 용도 |
|---|---|
| `prod-fdrace.bt` | production gcloud process 하나(`$1` = PID)의 fd 생성·close, 모든 I/O, 일반 파일 read/write, 원시 fd EBADF를 기록. TLS 모양 파일 write와 원시 fd use-after-close는 user stack까지 남김 |
| `prod-trace-supervisor.sh` | 서비스 MainPID를 따라 tracer를 다시 붙이고, DB 손상을 감지하면 증거를 자동 보존 |
| `fdrace.bt`, `fdrace3.bt` | 실험실용 tracer (초기판, EBADF와 stack 추가판) |
| `run.sh` | 격리 재현 환경: 복사한 설정으로 별도 tunnel을 띄우고 tracer 부착, 점검, 정리 |
| `load.py` | 무작위·순차 부하 (full / abrupt / RST 혼합) |
| `pair.py`, `pair2.py` | 표적 부하: 연결 A를 닫는 순간에 B를 연결. `pair2.py`는 pgjdbc처럼 TLS handshake 후 Terminate를 보내고 닫음 |
| `hunt.sh` | 500연결 단위로 반복하며 손상이나 적중이 나오면 멈춤 |
| `analyze.py` | tracer 로그에서 DB fd에 대한 비 sqlite I/O(적중), 이전 socket 사용자의 접근, EBADF를 집계 |

`tools/`는 조사 당시 환경(경로, 서비스 이름, 포트)을 그대로 담고 있다. 다른 환경에서 쓰려면 경로와 PID 등을 고쳐야 한다. 운영 process에 bpftrace를 붙일 때는 root 권한이 필요하고, 부하가 조금 생긴다.

## 가림 처리

공개를 위해 아래 정보를 치환했다: GCP 프로젝트 ID(`<PROJECT>`), 계정 이메일(`<ACCOUNT>`), 사설·공인 IP(`<CLIENT_IP>`, `<GCP_VM_IP>`, `<PUBLIC_IP>`), OCI OCID(`<OCID>`), gcloud invocation-id(`<ID>`), 호스트명(`host-a`, `host-b`), Slack webhook.
