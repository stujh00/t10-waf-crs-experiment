import argparse
import hashlib
import json
import random
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

parser = argparse.ArgumentParser()
parser.add_argument("--check-only", action="store_true")
parser.add_argument("--rounds", type=int, default=10)
args = parser.parse_args()
if not 1 <= args.rounds <= 10:
    raise SystemExit("반복 횟수는 1~10이어야 합니다.")

root = Path.home() / "t10-waf"
address = "203.0.113.10"
cert = Path("/etc/nginx/t10/tls/server.crt")
data = (root / "cases/cases_main.json").read_bytes()
digest = hashlib.sha256(data).hexdigest()
expected = "9404e81f0804d72556fcc06a2909928a6f80d2a65713945517254e7018730aef"

if digest != expected:
    raise SystemExit("입력 파일 해시가 다릅니다. 중단합니다.")
cases = json.loads(data)
assert len(cases) == 120

def send(scheme, pl, payload, request_id):
    port = 443 if scheme == "https" else 80
    uri = f"/pl{pl}/?" + urlencode({"q": payload})
    command = [
        "curl", "--noproxy", "*", "--silent", "--show-error",
        "--http1.1", "--connect-timeout", "5", "--max-time", "15",
        "--connect-to", f"{address}:{port}:127.0.0.1:{port}",
        "--header", f"X-T10-ID: {request_id}",
        "--header", "User-Agent: T10-WAF-Experiment/1.0",
        "--header", "Accept: */*",
        "--output", "/dev/null", "--write-out", "%{json}",
    ]
    if scheme == "https":
        command += ["--cacert", str(cert)]
    command.append(f"{scheme}://{address}{uri}")
    response = subprocess.run(command, capture_output=True, text=True)
    try:
        metrics = json.loads(response.stdout)
    except json.JSONDecodeError:
        metrics = {}
    return {
        "public_uri": uri,
        "status": int(metrics.get("http_code", 0)),
        "curl_exit": response.returncode,
        "error": response.stderr.strip(),
        "metrics": metrics,
    }

if args.check_only:
    failed = False
    for scheme in ("http", "https"):
        for pl in (1, 2, 3):
            result = send(
                scheme, pl, "hello", "precheck-" + uuid.uuid4().hex
            )
            ok = result["curl_exit"] == 0 and result["status"] == 200
            failed = failed or not ok
            print(
                f"{scheme.upper()} PL{pl}: "
                f"HTTP {result['status']} / "
                f"{'정상' if ok else '확인 필요'}"
            )
            if result["error"]:
                print(result["error"])
    raise SystemExit(1 if failed else 0)
run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
run_id += "-" + uuid.uuid4().hex[:8]
out = root / "results" / run_id
out.mkdir(parents=True, exist_ok=False)
(out / "cases_main.json").write_bytes(data)

manifest = {
    "run_id": run_id,
    "started_utc": datetime.now(timezone.utc).isoformat(),
    "cases_sha256": digest,
    "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "certificate_sha256": hashlib.sha256(cert.read_bytes()).hexdigest(),
    "address": address,
    "rounds": args.rounds,
    "seed": 20261020,
    "expected_requests": 120 * 3 * 2 * args.rounds,
    "connection": "127.0.0.1 through public Nginx ports 80/443",
    "method": "GET",
    "curl_version": subprocess.check_output(
        ["curl", "--version"], text=True
    ),
}
manifest_file = out / "manifest.json"

def save_manifest():
    manifest_file.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

save_manifest()
print("저장 위치:", out, flush=True)
rng = random.Random(manifest["seed"])
count = 0
errors = 0

with (out / "responses.jsonl").open("x", encoding="utf-8") as log:
    for repeat in range(1, args.rounds + 1):
        jobs = [
            (scheme, pl, case)
            for scheme in ("http", "https")
            for pl in (1, 2, 3)
            for case in cases
        ]
        rng.shuffle(jobs)

        for scheme, pl, case in jobs:
            count += 1
            request_id = f"{run_id}-{count:05d}"
            result = send(scheme, pl, case["payload"], request_id)
            needs_review = (
                result["curl_exit"] != 0
                or result["status"] not in (200, 403)
            )
            errors += int(needs_review)
            record = {
                "request_id": request_id,
                "time_utc": datetime.now(timezone.utc).isoformat(),
                "repeat": repeat,
                "scheme": scheme,
                "pl": pl,
                "case_id": case["id"],
                "label": case["label"],
                "category": case["category"],
                "payload": case["payload"],
                "needs_review": needs_review,
                **result,
            }
            log.write(json.dumps(record, ensure_ascii=False) + "\n")
            log.flush()
            if needs_review:
                manifest["recorded_requests"] = count
                manifest["needs_review"] = errors
                manifest["stopped_reason"] = "unexpected_response"
                save_manifest()
                raise SystemExit(
                    f"실험 중단: 요청 {request_id}, "
                    f"HTTP {result['status']}, "
                    f"curl 종료 코드 {result['curl_exit']}, "
                    f"오류: {result['error']}"
                )
            time.sleep(0.03)

        manifest["recorded_requests"] = count
        manifest["needs_review"] = errors
        save_manifest()
        print(
            f"{repeat}회 완료: {count}/{manifest['expected_requests']}건"
            f" / 확인 필요 {errors}건",
            flush=True,
        )

manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
save_manifest()
print("전체 실행 완료:", out, flush=True)
