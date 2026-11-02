"""Reproducible OFFLINE QA check for Step 44 structural URL warnings.

Historical reference URLs are benign structural examples, not proof their pages
are currently available/safe. Deceptive URLs use reserved .invalid domains,
NOT known live phishing sites. Never makes a network request.
"""
from pathlib import Path
import csv
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from phishguard.url_policy import assess_url
DATA = ROOT / 'data'


def read_urls(path):
    with path.open(encoding='utf-8-sig', newline='') as fh:
        return [row['url'] for row in csv.DictReader(fh)]


def run():
    safe=read_urls(DATA / 'step44_reference_benign_30.csv')
    deceptive=read_urls(DATA / 'step44_deceptive_qa_examples.csv')
    safe_out=[{'url':u,'indicator':assess_url(u).indicator,'status':assess_url(u).status} for u in safe]
    deceptive_out=[{'url':u,'indicator':assess_url(u).indicator,'status':assess_url(u).status} for u in deceptive]
    result = {
        'method':'offline conservative URL-structure screening, not phishing classifier accuracy',
        'reference_benign_n':len(safe),
        'reference_benign_high_alert_n':sum(x['indicator']>=45 for x in safe_out),
        'synthetic_deceptive_n':len(deceptive),
        'synthetic_deceptive_detected_high_n':sum(x['indicator']>=75 for x in deceptive_out),
        'known_limits':['no live DNS/domain ownership check','no URL content check','not independent real-world malware/phishing evaluation','no proof of safety when low risk','URL heuristic not a calibrated fraud probability'],
        'reference_samples':safe_out,
        'deceptive_qa_samples':deceptive_out,
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return result

if __name__ == '__main__':
    run()
