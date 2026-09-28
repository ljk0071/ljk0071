#!/usr/bin/env python3
"""template.html + evidence/ + tools/prod-fdrace.bt → ../gcloud-iap-fd-race.html

evidence/ 는 이미 가림 처리된 발췌다. 새 증거를 추가할 때를 대비해 같은 가림 규칙을
빌드 때 한 번 더 적용하고, 마지막에 가림 검사(0건이어야 함)를 한다.

    python3 build.py            # ../gcloud-iap-fd-race.html 갱신
    python3 build.py out.html   # 다른 경로로 출력
"""
import html
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
EVID = HERE / "evidence"
OUT = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parent / "gcloud-iap-fd-race.html"

# 일반 규칙: 사설·공인 IP, 이메일, OCID, invocation-id, Slack webhook.
# 프로젝트 전용 값(프로젝트 ID, 호스트명 등)은 이 파일에 적지 않는다. 필요하면
# 커밋하지 않는 .sanitize-extra 파일에 "정규식<TAB>치환값" 형식으로 한 줄씩 적는다.
SANITIZE = [
    (r"[\w.+-]+@[\w-]+\.iam\.gserviceaccount\.com", "<ACCOUNT>"),
    (r"[\w.+-]+@[\w-]+\.(com|net|org|io|co\.kr)\b", "<ACCOUNT>"),
    (r"\b10\.0\.0\.\d{1,3}\b", "<CLIENT_IP>"),
    (r"\b10\.138\.\d{1,3}\.\d{1,3}\b", "<GCP_VM_IP>"),
    (r"\b(?!10\.|127\.|169\.254\.|35\.235\.)(?:\d{1,3}\.){3}\d{1,3}\b(?=[^\d.]|$)", "<PUBLIC_IP>"),
    (r"ocid1\.[\w.-]+", "<OCID>"),
    (r"invocation-id/[0-9a-f]+", "invocation-id/<ID>"),
    (r"hooks\.slack\.com/\S+", "<REDACTED>"),
]
EXTRA = HERE / ".sanitize-extra"
if EXTRA.exists():
    for line in EXTRA.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            pat, rep = line.split("\t", 1)
            SANITIZE.insert(0, (pat, rep))
LEAK = re.compile("|".join([r"\b10\.0\.0\.\d", r"\b10\.138\.", r"ocid1\.", r"hooks\.slack", r"ya29\.",
                            r"@[\w-]+\.iam\.gserviceaccount", r"invocation-id/[0-9a-f]{8}"]
                           + [p for p, _ in SANITIZE[:len(SANITIZE) - 8]]))


def sanitize(text: str) -> str:
    for pat, rep in SANITIZE:
        text = re.sub(pat, rep, text)
    return text


def read(p: pathlib.Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def keep(text: str, pred) -> str:
    return "\n".join(l for l in text.splitlines() if pred(l))


# 템플릿의 <!--E:이름--> 자리에 들어갈 증거 (HTML escape 해서 <pre><code> 안에 넣음)
PARTS = {
    "source": read(EVID / "source-excerpts.txt"),
    "ab": read(EVID / "ab-test.txt"),
    "c0924": read(EVID / "corruption-0924.txt"),
    "c0925": "\n".join(read(EVID / "corruption-0925-window.txt").splitlines()[:32]),
    "trace": read(EVID / "trace-excerpt.txt"),
    "glog": read(EVID / "gcloud-log-excerpt.txt"),
    # fd 7 과 use-after-close 표시 줄만 (stdout/stderr 쓰기는 제외)
    "near": keep(read(EVID / "near-miss.txt"),
                 lambda l: l.startswith("###") or " fd=7 " in l or l.rstrip().endswith("fd=7")
                 or "RAW-FD" in l or "ustack" in l or "__GI_read" in l),
    "lab": read(EVID / "lab-stats.txt"),
    "hex": read(EVID / "db-hex.txt"),
    "errs": keep(read(EVID / "gcloud-errors.txt"),
                 lambda l: "current gcloud stderr" not in l and "No such file" not in l),
    "bt": read(HERE / "tools" / "prod-fdrace.bt"),
}

page = read(HERE / "template.html")
for key, val in PARTS.items():
    marker = f"<!--E:{key}-->"
    assert marker in page, marker
    page = page.replace(marker, html.escape(sanitize(val).rstrip()))

# 타임라인은 이 원문을 브라우저에서 파싱한다 (<script type="text/plain">, escape 하지 않음)
trace_raw = sanitize(read(EVID / "trace-excerpt.txt"))
assert "</" not in trace_raw
page = page.replace("<!--E:traceRaw-->", trace_raw)
assert "<!--E:" not in page, "채워지지 않은 자리표시자가 남음"

OUT.write_text(page, encoding="utf-8")
hits = [(i + 1, m.group(0)) for i, line in enumerate(page.splitlines()) for m in LEAK.finditer(line)]
print(f"wrote {OUT} ({OUT.stat().st_size:,} bytes); leak hits: {len(hits)}")
for h in hits[:20]:
    print("  LEAK", h)
sys.exit(1 if hits else 0)
