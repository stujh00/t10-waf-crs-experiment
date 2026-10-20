import json
from pathlib import Path

sqli = [
    "' OR 2=2 -- ",
    "' OR 'x'='x' -- ",
    "admin' OR 'a'='a' -- ",
    "') OR ('a'='a') -- ",
    "1 OR 2=2",
    "1 OR TRUE",
    "1' OR TRUE -- ",
    "1 OR 3>2",
    "1 OR 2 BETWEEN 1 AND 3",
    "1 OR 2 IN (1,2,3)",
    "1 OR 'ab' LIKE 'a%'",
    "1 OR LENGTH('abc')=3",
    "1 OR ASCII('A')=65",
    "1 OR LOWER('ABC')='abc'",
    "1 OR CONCAT('a','b')='ab'",
    "1 UNION SELECT NULL -- ",
    "1 UNION SELECT NULL,NULL -- ",
    "1 UNION SELECT 1,2,3 -- ",
    "' UNION SELECT 'a','b' -- ",
    "1 UNION ALL SELECT 1,2 -- ",
    "1 UNION SELECT database(),user() -- ",
    "1 UNION SELECT table_name FROM information_schema.tables -- ",
    "1 UNION SELECT column_name FROM information_schema.columns -- ",
    "1 UNION SELECT name FROM sqlite_master -- ",
    "1 UNION SELECT version() -- ",
    "1/**/OR/**/2=2",
    "'/**/OR/**/'a'='a'/**/-- ",
    "1/**/UNION/**/SELECT/**/NULL",
    "1 UnIoN SeLeCt NULL,NULL -- ",
    "1 oR 2=2 -- ",
]

xss = []
xss = [
    "<script>alert(1)</script>",
    "<SCRIPT>alert(2)</SCRIPT>",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    "<script>console.log(1)</script>",
    "<img src=x onerror=alert(1)>",
    '<img src="x" onerror="alert(2)">',
    "<IMG SRC=x ONERROR=alert(3)>",
    "<svg onload=alert(1)>",
    '<svg onload="alert(2)"></svg>',
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)></textarea>",
    "<select autofocus onfocus=alert(1)></select>",
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)></video>",
    "<audio src=x onerror=alert(1)></audio>",
    "<iframe onload=alert(1)></iframe>",
    '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
    '<a href="javascript:alert(1)">click</a>',
    "<a href=javascript:confirm(1)>click</a>",
    '<form action="javascript:alert(1)"><button>send</button></form>',
    '<button onclick="alert(1)">click</button>',
    '<div onmouseover="alert(1)">hover</div>',
    '<p onclick="alert(1)">click</p>',
    '<img src=x onerror="&#97;lert(1)">',
    '<a href="&#106;avascript:alert(1)">click</a>',
    '<svg><a href="javascript:alert(1)">click</a></svg>',
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<script>alert(document.domain)</script>",
]
assert len(sqli) == 30
assert len(xss) == 30

cases = []
for category, samples in (("sqli", sqli), ("xss", xss)):
    for payload in samples:
        cases.append({
            "id": f"A{len(cases) + 1:03d}",
            "label": "attack",
            "category": category,
            "payload": payload,
            "reason": "Attack-pattern test; exploit success is not established",
        })

assert len({c["payload"] for c in cases}) == 60

output = Path(__file__).parent / "attack_draft.json"
if output.exists():
    raise SystemExit("기존 파일이 있어 중단합니다: " + str(output))

output.write_text(
    json.dumps(cases, ensure_ascii=False, indent=2),
    encoding="utf-8",
)

print("저장:", output)
print("SQLi:", len(sqli), "개")
print("XSS:", len(xss), "개")
print("공격 테스트 입력:", len(cases), "개")
