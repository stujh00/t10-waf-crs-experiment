import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

folder = Path.home() / "t10-waf/results/20261020T005958Z-ca99f72b"
groups = defaultdict(Counter)
cases = defaultdict(Counter)
case_info = {}

with (folder / "responses.jsonl").open(encoding="utf-8") as f:
    for line in f:
        row = json.loads(line)

        group = (
            row["scheme"], row["pl"],
            row["label"], row["category"],
        )
        groups[group][row["status"]] += 1

        key = (row["scheme"], row["pl"], row["case_id"])
        cases[key][row["status"]] += 1
        case_info[key] = row

def save_csv(filename, rows):
    path = folder / filename
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print("저장:", path)

summary = []
for key, counts in sorted(groups.items()):
    scheme, pl, label, category = key
    total = sum(counts.values())
    blocked = counts[403]
    summary.append({
        "scheme": scheme,
        "pl": pl,
        "label": label,
        "category": category,
        "total_requests": total,
        "allowed_200": counts[200],
        "blocked_403": blocked,
        "other_status": total - counts[200] - blocked,
        "blocked_percent": round(blocked / total * 100, 2),
    })

details = []
for key, counts in sorted(cases.items()):
    row = case_info[key]
    details.append({
        "scheme": row["scheme"],
        "pl": row["pl"],
        "case_id": row["case_id"],
        "label": row["label"],
        "category": row["category"],
        "payload": row["payload"],
        "total_requests": sum(counts.values()),
        "allowed_200": counts[200],
        "blocked_403": counts[403],
        "status_changed": len(counts) > 1,
    })

save_csv("category-summary.csv", summary)
save_csv("case-results.csv", details)

names = {
    "ordinary": "일반 문장",
    "html_example": "HTML 설명",
    "technical_example": "기술 문서 설명",
}

for scheme in ("http", "https"):
    print(f"\n===== {scheme.upper()} 정상 입력 분류별 오탐 =====")
    for row in summary:
        if row["scheme"] != scheme or row["label"] != "benign":
            continue
        name = names.get(row["category"], row["category"])
        print(
            f"PL{row['pl']} | {name} | "
            f"{row['blocked_403']}/{row['total_requests']}건 차단 | "
            f"오탐률 {row['blocked_percent']:.2f}%"
        )
