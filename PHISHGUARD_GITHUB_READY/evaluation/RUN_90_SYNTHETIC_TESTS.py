"""Reproduce the 90-example synthetic development evaluation.

Run from the project folder: python evaluation/RUN_90_SYNTHETIC_TESTS.py
No network requests made. This is NOT an external real-world test.
"""
from pathlib import Path
from collections import Counter
import sys, csv, json
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from phishguard.inference import analyze_message
fixture_path=ROOT/'evaluation'/'90_Synthetic_Regression_Results.csv'
rows=list(csv.DictReader(fixture_path.open(encoding='utf-8-sig',newline='')))
results=[]
for row in rows:
    pred=analyze_message(row['message'])
    results.append({
        'message':row['message'],
        'language_expected':row['language_expected'],
        'expected_label':row['expected_label'],
        'predicted_label':pred['verdict'],
        'detected_language':pred['language_detected'],
        'risk_score':pred['risk_score'],
        'correct_verdict':int(pred['verdict']==row['expected_label']),
        'correct_language':int(pred['language_detected']==row['language_expected'])})
counts=Counter((r['expected_label'],r['predicted_label']) for r in results)
summary={'tests':len(results),'verdict_agreements':sum(r['correct_verdict'] for r in results),
         'language_matches':sum(r['correct_language'] for r in results),
         'confusion_counts':{f'{a} -> {b}':counts[(a,b)] for a in ('Safe','Suspicious','Scam') for b in ('Safe','Suspicious','Scam')},
         'IMPORTANT':'Synthetic manually assigned examples only; not real-world accuracy.'}
print(json.dumps(summary,indent=2,ensure_ascii=False))
output=ROOT/'evaluation'/'REPRODUCED_RESULTS.csv'
with output.open('w',encoding='utf-8-sig',newline='') as fd:
    w=csv.DictWriter(fd,fieldnames=list(results[0]));w.writeheader();w.writerows(results)
print('Detailed report saved to:',output)
