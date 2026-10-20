import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

folder = Path.home() / "t10-waf/results/20261020T005958Z-ca99f72b"
responses = {}
issues = Counter()
examples = []
seen = Counter()
allowed_rules = Counter()

def problem(kind, request_id):
    issues[kind] += 1
    if len(examples) < 10:
        examples.append([kind, request_id])

with (folder / "responses.jsonl").open(encoding="utf-8") as f:
    for line in f:
        row = json.loads(line)
        rid = row["request_id"]
        if rid in responses:
            problem("응답 기록의 요청 번호 중복", rid)
        responses[rid] = row

for pl in (1, 2, 3):
    path = folder / f"t10-pl{pl}-audit.jsonl"
    with path.open("rb") as f:
        for line in f:
            tx = json.loads(
                line.decode("utf-8", errors="replace")
            )["transaction"]
            request = tx.get("request", {})
            headers = request.get("headers", {})
            rid = next(
                (v for k, v in headers.items()
                 if k.lower() == "x-t10-id"),
                None,
            )
            if rid not in responses:
                continue

            seen[rid] += 1
            row = responses[rid]
            status = int(tx.get("response", {}).get("http_code", 0))
            q = parse_qs(
                urlsplit(request.get("uri", "")).query,
                keep_blank_values=True,
            ).get("q", [])
            rules = {
                str(m.get("details", {}).get("ruleId"))
                for m in tx.get("messages", [])
            }

            if row["pl"] != pl:
                problem("PL 불일치", rid)
            if q != [row["payload"]]:
                problem("입력 내용 불일치", rid)
            if status != row["status"]:
                problem("응답 번호 불일치", rid)
            if status == 403 and "949110" not in rules:
                problem("403의 점수 초과 차단 근거 없음", rid)
            if status == 200 and "949110" in rules:
                problem("200인데 점수 초과 차단 규칙 존재", rid)

            if row["case_id"] == "A006" and status == 200:
                allowed_rules.update(rules or {"탐지 메시지 없음"})

for rid in responses:
    if seen[rid] == 0:
        problem("WAF 로그 누락", rid)
    elif seen[rid] > 1:
        problem("WAF 로그 중복", rid)

report = {
    "response_ids": len(responses),
    "matched_ids": len(seen),
    "issues": dict(issues),
    "examples": examples,
    "A006_rules": dict(allowed_rules),
}
output = folder / "audit-verification.json"
output.write_text(
    json.dumps(report, ensure_ascii=False, indent=2),
    encoding="utf-8",
)

print("응답 기록의 고유 요청:", len(responses))
print("WAF 로그에서 찾은 고유 요청:", len(seen))
print("문제 항목:", dict(issues) or "없음")
print("문제 예시:", examples or "없음")
print("A006 허용 요청의 탐지 규칙:", dict(allowed_rules))
print("검증 결과 저장:", output)
