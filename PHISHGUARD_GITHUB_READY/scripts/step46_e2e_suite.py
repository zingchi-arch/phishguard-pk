"""Offline end-to-end QA on 36 hand-authored synthetic cases.

WARNING: This is a deterministic regression/safety check, NOT independent
real-world model accuracy. No suspect URL is opened or fetched. The script
runs the local FastAPI app in-process (TestClient) for repeatability.
"""
from __future__ import annotations
import argparse
import csv
import json
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from fastapi.testclient import TestClient
from phishguard.api import app

DEFAULT_CASES=ROOT/'evaluation'/'STEP46_36_SYNTHETIC_REGRESSION_NOT_REAL.csv'


def evaluate(cases:Path=DEFAULT_CASES):
    with cases.open('r',encoding='utf-8-sig',newline='') as fh:
        rows=list(csv.DictReader(fh))
    if not rows or any(r['source_type']!='HAND_AUTHORED_SYNTHETIC_QA' or r['eligible_for_external_accuracy']!='NO' for r in rows):
        raise ValueError('Step46 test suite accepts only explicitly synthetic QA cases')
    client=TestClient(app)
    api_checks={
        'health':client.get('/health').status_code==200,
        'model_status':client.get('/model-status').status_code==200,
        'reject_empty':client.post('/analyze',json={'message':'  '}).status_code==422,
        'reject_too_long':client.post('/analyze',json={'message':'z'*10001}).status_code==422,
        'reject_batch_over_100':client.post('/analyze/batch',json={'messages':['ok']*101}).status_code==422,
        'reject_long_explanation':client.post('/analyze/explain',json={'message':'a'*901}).status_code==422,
        'single_message':client.post('/analyze',json={'message':'Eid Mubarak!'}).status_code==200,
        'batch_message':client.post('/analyze/batch',json={'messages':['hello','hi']}).status_code==200,
    }
    results=[]
    for row in rows:
        response=client.post('/analyze',json={'message':row['message']})
        if response.status_code!=200:
            row.update(actual_verdict='API_ERROR',risk_score='',qa_pass='NO',why=f'HTTP {response.status_code}')
        else:
            obj=response.json()
            verdict=obj['verdict']; expected=row['expected_behavior']
            ok = verdict=='Scam' if expected=='Scam' else verdict!='Scam'
            row.update(actual_verdict=verdict,risk_score=obj['risk_score'],qa_pass='YES' if ok else 'NO',
                why='Met expected conservative rule behavior' if ok else 'Unexpected QA verdict')
        results.append(row)
    breakdown={}
    for lang in sorted({r['language'] for r in results}):
        group=[r for r in results if r['language']==lang]
        breakdown[lang]={'n':len(group),'qa_pass':sum(r['qa_pass']=='YES' for r in group)}
    report={'type':'HAND_AUTHORED_SYNTHETIC_REGRESSION_NOT_REAL_PERFORMANCE',
      'run_time_utc':datetime.now(timezone.utc).isoformat(),
      'source_type':'synthetic QA scenarios, NOT observed SMS',
      'total':len(results),'qa_pass':sum(r['qa_pass']=='YES' for r in results),
      'by_language':breakdown,'api_checks':api_checks,
      'warnings':['Not independent evaluation. Not phishing detection accuracy.',
                  'Messages were designed by development team. No external source verified.',
                  'Any unexpected scenario requires review; adjusting the test to force passing is not evaluation.']}
    return report, results


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--cases',type=Path,default=DEFAULT_CASES)
    p.add_argument('--out',type=Path,default=ROOT/'reports'/'step46')
    a=p.parse_args()
    report,rows=evaluate(a.cases)
    a.out.mkdir(parents=True,exist_ok=True)
    (a.out/'step46_synthetic_QA_report.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    with (a.out/'step46_synthetic_QA_details.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
    print(json.dumps(report,indent=2,ensure_ascii=False))
    return 0 if all(report['api_checks'].values()) else 1

if __name__=='__main__':
    raise SystemExit(main())
