import json
from collections import Counter, defaultdict
from pathlib import Path

folder = Path.home() / "t10-waf/results/20261020T005958Z-ca99f72b"

allowed = Counter()
outcomes = defaultdict(set)
repeats = Counter()

with (folder / "responses.jsonl").open(encoding="utf-8") as f:
    for line in f:
        row = json.loads(line)

        key = (row["scheme"], row["pl"], row["case_id"])
        outcomes[key].add(row["status"])
        repeats[key] += 1

        if row["label"] == "attack" and row["status"] == 200:
            allowed[
                row["scheme"], row["pl"], row["case_id"],
                row["category"], row["payload"]
            ] += 1

print("===== WAF가 허용한 공격 테스트 입력 =====")
for key, count in sorted(allowed.items()):
    scheme, pl, case_id, category, payload = key
    print(f"\n{scheme.upper()} PL{pl} | {case_id} | {category}")
    print("입력:", payload)
    print("허용 횟수:", count)

changed = [key for key, values in outcomes.items() if len(values) > 1]
wrong_count = [key for key, count in repeats.items() if count != 10]

print("\n===== 반복 결과 확인 =====")
print("확인한 조건·입력 조합:", len(outcomes), "/ 예상 720")
print("반복 중 응답이 달라진 조합:", len(changed))
print("기록 수가 10건이 아닌 조합:", len(wrong_count))

for key in changed[:10]:
    print("응답 변화:", key, sorted(outcomes[key]))
for key in wrong_count[:10]:
    print("반복 수 확인 필요:", key, repeats[key])
