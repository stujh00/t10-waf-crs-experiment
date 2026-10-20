import json
from pathlib import Path

groups = {
    "ordinary": [
        "배송 예정일을 알려주세요",
        "지난달 주문 내역 확인",
        "비밀번호 변경 방법 안내",
        "회의실 예약 가능 시간",
        "제품 A와 제품 B 비교",
        "문의 번호 2026-1042",
        "O'Connor 고객의 예약 확인",
        "가격은 15,000원입니다",
        "매장 운영 시간 09:00~18:00",
        "연락처 user@example.com",
    ],
    "html_example": [
        "<h2>Introduction</h2>",
        "<p>First paragraph</p>",
        "<strong>Important notice</strong>",
        "<em>Example sentence</em>",
        "<ul><li>Apple</li></ul>",
        "<ol><li>First step</li></ol>",
        "<table><tr><td>Item</td></tr></table>",
        '<a href="/guide">User guide</a>',
        '<img src="/sample.png" alt="Example">',
        "<blockquote>Quoted sentence</blockquote>",
    ],
    "technical_example": [
        "SELECT product_name FROM products;",
        "SELECT COUNT(*) FROM orders;",
        "SELECT name FROM users WHERE id = 7;",
        "SELECT category, COUNT(*) FROM products GROUP BY category;",
        "SELECT name FROM products ORDER BY name;",
        "INSERT INTO products (name) VALUES ('Notebook');",
        "UPDATE products SET name = 'Pen' WHERE id = 7;",
        "CREATE TABLE sample (id INT, name VARCHAR(40));",
        'if (count > 0) { print("available"); }',
        "result = items[1:4]",
    ],
}

cases = []
for category, samples in groups.items():
    for number, sample in enumerate(samples, 1):
        if category == "ordinary":
            variants = [
                ("ko", "검색 요청: " + sample),
                ("en", "Search request: " + sample),
            ]
        else:
            variants = [
                ("ko", "다음 코드를 문자로 설명하는 문서입니다: " + sample),
                ("en", "Documentation showing this code as literal text: " + sample),
            ]

        for wrapper, payload in variants:
            cases.append({
                "id": f"B{len(cases) + 1:03d}",
                "label": "benign",
                "category": category,
                "base_id": f"{category}-{number:02d}",
                "wrapper_language": wrapper,
                "payload": payload,
                "reason": "Input is permitted as literal text by the lab policy",
            })

assert len(cases) == 60
assert len({c["payload"] for c in cases}) == 60

output = Path(__file__).parent / "benign_draft.json"
if output.exists():
    raise SystemExit("기존 파일이 있어 중단합니다: " + str(output))

output.write_text(
    json.dumps(cases, ensure_ascii=False, indent=2),
    encoding="utf-8",
)

print("저장:", output)
print("정상 요청:", len(cases), "개")
for category in groups:
    print(category, sum(c["category"] == category for c in cases), "개")
