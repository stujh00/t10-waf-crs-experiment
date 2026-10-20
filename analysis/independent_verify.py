"""Offline verification; standard library only; no requests are sent."""
import csv
import hashlib
import itertools
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / 'raw'
run = root / 'results/20261020T005958Z-ca99f72b'
out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).parent / 'verified'
out.mkdir(parents=True, exist_ok=True)
issues = []
hash_lines = (root/'SHA256SUMS.txt').read_text().splitlines()
for line in hash_lines:
    digest, name = line.split('  ', 1)
    path = (root/name).resolve()
    assert path.is_relative_to(root.resolve())
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        issues.append(['archive_hash', name])
manifest = json.loads((run/'manifest.json').read_text())
corpus = json.loads((run/'cases_main.json').read_text())
by_case = {c['id']: c for c in corpus}
for path, digest in [(run/'cases_main.json', manifest['cases_sha256']),
                     (root/'run_main.py', manifest['script_sha256'])]:
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        issues.append(['manifest_hash', str(path)])
records = {}
coverage = Counter()
summary = Counter()
paired = defaultdict(dict)
for line in (run/'responses.jsonl').open(encoding='utf-8'):
    r = json.loads(line)
    rid = r['request_id']
    if rid in records: issues.append(['duplicate_response',rid])
    records[rid] = r
    c = by_case[r['case_id']]
    if any(r[k] != c[k] for k in ['payload','label','category']):
        issues.append(['case_content',rid])
    if r['curl_exit'] or r['needs_review'] or r['status'] not in (200,403):
        issues.append(['response_error',rid])
    coverage[r['scheme'],r['pl'],r['case_id'],r['repeat']] += 1
    summary[r['scheme'],r['pl'],r['label'],r['category'],r['status']] += 1
    paired[r['pl'],r['case_id'],r['repeat']][r['scheme']] = r['status']
expected = set(itertools.product(['http','https'],[1,2,3],by_case,range(1,11)))
if set(coverage) != expected or any(n != 1 for n in coverage.values()):
    issues.append(['coverage',len(coverage)])
seen = Counter()
rule_counts = Counter()
rule_details = []
invalid_utf8 = Counter()
parse_errors = Counter()
public_derivative = True
for pl in [1,2,3]:
    with (run/f't10-pl{pl}-audit.jsonl').open('rb') as f:
        for line_no, line in enumerate(f,1):
            try: text = line.decode('utf-8')
            except UnicodeDecodeError:
                invalid_utf8[pl] += 1
                text = line.decode('utf-8',errors='replace')
            try: tx = json.loads(text)['transaction']
            except (json.JSONDecodeError,KeyError):
                parse_errors[pl] += 1
                continue
            req = tx.get('request',{})
            headers = {k.lower():v for k,v in req.get('headers',{}).items()}
            rid = headers.get('x-t10-id')
            if rid not in records: continue
            seen[rid] += 1
            r = records[rid]
            if r['pl'] != pl: issues.append(['audit_pl',rid])
            if req.get('method') != 'GET': issues.append(['method',rid])
            if headers.get('host') != 'lab.example.test': issues.append(['host',rid])
            if headers.get('user-agent') != 'T10-WAF-Experiment/1.0': issues.append(['agent',rid])
            if headers.get('accept') != '*/*': issues.append(['accept',rid])
            uri = urlsplit(req.get('uri',''))
            if uri.path != '/' or parse_qs(uri.query,keep_blank_values=True).get('q') != [r['payload']]:
                issues.append(['audit_uri',rid])
            if int(tx.get('response',{}).get('http_code',0)) != r['status']:
                issues.append(['audit_status',rid])
            messages = tx.get('messages',[])
            rules = {str(m.get('details',{}).get('ruleId')) for m in messages}
            if (r['status']==403) != ('949110' in rules): issues.append(['block_rule',rid])
            for rule in rules:
                rule_counts[r['scheme'],pl,r['label'],r['category'],rule] += 1
            if r['repeat']==1 and r['scheme']=='http' and r['label']=='benign':
                for m in messages:
                    rule_details.append({'case_id':r['case_id'],'pl':pl,'category':r['category'],
                        'payload':r['payload'],'rule_id':str(m.get('details',{}).get('ruleId')),
                        'message':m.get('message'),'match':m.get('details',{}).get('match'),
                        'data':m.get('details',{}).get('data')})
for rid in records:
    if seen[rid] != 1: issues.append(['audit_coverage',rid,seen[rid]])
pair_diffs = sum(v.get('http') != v.get('https') for v in paired.values())
stability = defaultdict(set)
for r in records.values(): stability[r['scheme'],r['pl'],r['case_id']].add(r['status'])
changed = sum(len(v)>1 for v in stability.values())
summary_rows=[]
for scheme,pl,label,category in sorted({k[:4] for k in summary}):
    allowed=summary[scheme,pl,label,category,200];blocked=summary[scheme,pl,label,category,403]
    summary_rows.append(dict(scheme=scheme,pl=pl,label=label,category=category,
        total=allowed+blocked,allowed=allowed,blocked=blocked,blocked_percent=100*blocked/(allowed+blocked)))
with (out/'verified_categories.csv').open('w',encoding='utf-8-sig',newline='') as f:
    w=csv.DictWriter(f,fieldnames=summary_rows[0]);w.writeheader();w.writerows(summary_rows)
report=dict(public_derivative=True,certificate_verified=False,hash_files=len(hash_lines),requests=len(records),audit_matched=len(seen),
    coverage_combinations=len(coverage),paired_http_https=len(paired),paired_differences=pair_diffs,
    repeat_changed=changed,invalid_utf8_lines=dict(invalid_utf8),json_parse_errors=dict(parse_errors),
    input_cases=len(corpus),issues=issues,passed=not issues and pair_diffs==0 and changed==0)
(out/'independent-verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
(out/'rule-match-examples.json').write_text(json.dumps(rule_details,ensure_ascii=False,indent=2))
print(json.dumps(report,ensure_ascii=False,indent=2))
if not report['passed']: sys.exit(1)
