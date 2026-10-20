import csv
import json
from collections import Counter
from pathlib import Path

folder = Path.home() / "t10-waf/results/20261020T005958Z-ca99f72b"
targets = {}
counts = Counter()
messages = {}

with (folder / "responses.jsonl").open(encoding="utf-8") as f:
    for line in f:
        row = json.loads(line)
        if row["label"] == "benign" and row["status"] == 403:
            targets[row["request_id"]] = row

for pl in (1, 2, 3):
    with (folder / f"t10-pl{pl}-audit.jsonl").open("rb") as f:
        for line in f:
            tx = json.loads(
                line.decode("utf-8", errors="replace")
            )["transaction"]
            headers = tx.get("request", {}).get("headers", {})
            rid = next(
                (v for k, v in headers.items()
                 if k.lower() == "x-t10-id"),
                None,
            )
            if rid not in targets:
                continue

            row = targets[rid]
            found = set()

            for message in tx.get("messages", []):
                rule = str(message.get("details", {}).get("ruleId", ""))
                if not rule or rule == "949110" or rule in found:
                    continue
                found.add(rule)

                key = (
                    row["scheme"], pl, row["category"], rule,
                )
                counts[key] += 1
                messages[rule] = message.get("message", "")

rows = []
for key, count in sorted(counts.items()):
    scheme, pl, category, rule = key
    rows.append({
        "scheme": scheme,
        "pl": pl,
        "category": category,
        "rule_id": rule,
        "blocked_requests_with_rule": count,
        "message": messages[rule],
    })

path = folder / "benign-rule-summary.csv"
with path.open("w", encoding="utf-8-sig", newline="") as f:
    fields = [
        "scheme", "pl", "category", "rule_id",
        "blocked_requests_with_rule", "message",
    ]
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

print("저장:", path)
print("\n===== HTTP 정상 입력 차단에서 나타난 규칙 =====")
print("HTTPS 결과도 CSV 파일에 별도로 저장했습니다.")

for pl in (1, 2, 3):
    for category in ("ordinary", "html_example", "technical_example"):
        selected = [
            row for row in rows
            if row["scheme"] == "http"
            and row["pl"] == pl
            and row["category"] == category
        ]
        selected.sort(
            key=lambda row: (-row["blocked_requests_with_rule"], row["rule_id"])
        )
        print(f"\nPL{pl} | {category} | 상위 3개 규칙")
        if not selected:
            print("차단 요청의 탐지 규칙 없음")
        for row in selected[:3]:
            print(
                row["rule_id"], "|",
                row["blocked_requests_with_rule"], "건 |",
                row["message"],
            )
