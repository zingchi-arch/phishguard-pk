"""Step48: run reproducible OFFLINE URL screening comparisons.

Input ZIP is a previous public UCI *candidate* subset, NOT independently
reviewed current live phishing URLs. A prior supervised RF model was trained
on the SAME SOURCE FAMILY, with unknown row overlap; results are diagnostic
only and MUST NOT be presented as external/independent accuracy.

No URL is ever opened, downloaded, resolved, or followed.
Do not copy the raw input ZIP into public GitHub or production deployments.

Usage:
  python scripts/step48_url_benchmark.py \
    --input-zip /private/PhishGuard_PK_Expanded_Source_Data_Audit.zip \
    --model-zip /private/PhishGuard_Step28_Real_URL_Model_Results.zip \
    --output /private/step48_results
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import io
import json
import sys
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from phishguard.url_policy import assess_url

LABEL_MAP = {'0': 'phishing', '1': 'legitimate'}
PUBLIC_SOURCE_TOKEN = 'UCI PhiUSIIL 2024'
URL_CSV = 'URL_10000_STRATIFIED_CANDIDATES.csv'
MODEL_ENTRY = 'PHISHGUARD_GITHUB_READY/models/url_model_real.joblib'


def load_public_candidates(archive: Path) -> list[dict]:
    """Label orientation from original source: 0=phishing, 1=legitimate."""
    with zipfile.ZipFile(archive) as z:
        if URL_CSV not in z.namelist():
            raise ValueError(f'Missing {URL_CSV}')
        r = csv.DictReader(io.TextIOWrapper(z.open(URL_CSV), encoding='utf-8-sig'))
        if not {'url','label_uci','label','source'}.issubset(r.fieldnames or []):
            raise ValueError('Source URL dataset schema mismatch')
        result = []
        seen = set()
        for row in r:
            url = row['url'].strip()
            number = row['label_uci'].strip()
            if not url or number not in LABEL_MAP or LABEL_MAP[number] != row['label'].strip().lower():
                raise ValueError('Invalid or conflicting UCI URL label')
            if PUBLIC_SOURCE_TOKEN not in row['source']:
                raise ValueError('Unexpected source: no silent mixing across datasets')
            if url in seen:
                raise ValueError('Duplicate URL: evaluate distinct rows separately only with explicit policy')
            seen.add(url)
            result.append({'url':url,'true':LABEL_MAP[number]})
    if not result:
        raise ValueError('Empty data file')
    return result


def confusion(rows: list[tuple[str, bool]]) -> dict:
    """Treat warning as predicted phishing and not-warning as predicted legitimate."""
    tp=sum(truth=='phishing' and warn for truth,warn in rows)
    fn=sum(truth=='phishing' and not warn for truth,warn in rows)
    fp=sum(truth=='legitimate' and warn for truth,warn in rows)
    tn=sum(truth=='legitimate' and not warn for truth,warn in rows)
    return {'phishing_flagged_TP':tp,'phishing_missed_FN':fn,
            'legitimate_warned_FP':fp,'legitimate_not_warned_TN':tn,
            'phishing_recall':round(tp/max(1,tp+fn),4),
            'legitimate_false_alarm_rate':round(fp/max(1,fp+tn),4),
            'confusion_labels':['legitimate','phishing'],
            'confusion_rows_true_columns_predicted':[[tn,fp],[fn,tp]]}


def assess_rows(entries: list[dict]) -> tuple[dict,list[dict]]:
    evaluated=[]
    for entry in entries:
        u=entry['url']
        assessment=assess_url(u)
        evaluated.append({'truth':entry['true'], 'indicator':assessment.indicator,
                          'url_sha256':hashlib.sha256(u.encode('utf-8')).hexdigest(),
                          'structural_warning':assessment.indicator>=45})
    baseline=confusion([(r['truth'],r['structural_warning']) for r in evaluated])
    return baseline,evaluated


def existing_rf_diagnostic(entries: list[dict], model_zip: Path,
                           benign_references: Path) -> dict:
    """Evaluate a historical model without ever installing it in live /models."""
    import joblib
    import numpy as np
    from phishguard.urls import feature_vector
    with zipfile.ZipFile(model_zip) as z:
        if MODEL_ENTRY not in z.namelist():
            raise ValueError('Expected historical URL model missing')
        with tempfile.TemporaryDirectory(prefix='phishguard_step48_') as tmp:
            path=z.extract(MODEL_ENTRY, tmp)
            # Only load a model ZIP supplied by a trusted developer: joblib
            # deserialization can execute code. Do NOT accept untrusted archives.
            model=joblib.load(path)
            if list(model.classes_) != [0,1] or model.n_features_in_ != len(feature_vector('https://example.org')):
                raise ValueError('Historical model label direction or feature count mismatch')
            values=np.asarray([feature_vector(e['url']) for e in entries],dtype=np.float32)
            probs=np.asarray(model.predict_proba(values)[:,1],dtype=float)
            if not np.isfinite(probs).all() or ((probs<0)|(probs>1)).any():
                raise ValueError('Bad RF raw score')
            with benign_references.open(encoding='utf-8-sig',newline='') as f:
                br=[r['url'].strip() for r in csv.DictReader(f) if r.get('url','').strip()]
            benign_scores=np.asarray(model.predict_proba(
                np.asarray([feature_vector(x) for x in br],dtype=np.float32))[:,1],dtype=float)
            thresholds={}
            for t in (0.5,0.9,0.99):
                thresholds[str(t)]=dict(confusion([(e['true'],float(p)>=t) for e,p in zip(entries,probs)]),
                    repeated_benign_30_reference_false_alarms=int((benign_scores>=t).sum()))
            return {'model':'Step28 historical 15-feature UCI RF',
                    'not_independent':'Model and benchmark share UCI PhiUSIIL origin; training-record overlap cannot be excluded.',
                    'post_hoc_threshold_sweep_not_valid_for_final_selection':True,
                    'reference_benign_reused_not_blind':True,
                    'thresholds':thresholds}


def main(input_zip:Path, output:Path, model_zip:Path|None=None,
         benign_reference:Path|None=None) -> dict:
    entries=load_public_candidates(input_zip)
    source_counts=dict(Counter(e['true'] for e in entries))
    base,rows=assess_rows(entries)
    output.mkdir(parents=True,exist_ok=True)
    report={
        'study':'STEP48_OFFLINE_SOURCE_LABEL_URL_BENCHMARK_NOT_INDEPENDENT',
        'candidate_records':len(entries), 'source_label_counts':source_counts,
        'labels':'Original UCI PhiUSIIL: label_uci=0 phishing, 1 legitimate',
        'dataset_2024_not_current':'Current URLs and Pakistan relevance are unverified.',
        'no_URL_fetched_or_opened':True,
        'structural_threshold_45_warning':base,
        'supervised_url_model_deployment_approved':False,
        'real_world_accuracy_claim_permitted':False,
        'external_2026_url_evaluation':'NOT_AVAILABLE',
        'methodology':'Source-specific diagnostic, not 2026 live attack performance or blind holdout.',
        'decision':'Hold current conservative structural policy. Independently validate supervised RF before deploying.'
    }
    if model_zip is not None:
        report['historical_RF_RESEARCH_ONLY']=existing_rf_diagnostic(entries,model_zip,benign_reference or ROOT/'data'/'step44_reference_benign_30.csv')
    (output/'STEP48_URL_BENCHMARK_METRICS.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    # Even when public dataset exists, publishing the URLs risks spreading a
    # list of phishing destinations. Export ONLY hashes and high-level flags.
    with (output/'STEP48_HASHED_DIAGNOSTIC_PRIVATE.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--input-zip',type=Path,required=True)
    p.add_argument('--model-zip',type=Path)
    p.add_argument('--output',type=Path,default=Path.home()/'phishguard_step48_private_results')
    a=p.parse_args()
    print(json.dumps(main(a.input_zip,a.output,a.model_zip),indent=2,ensure_ascii=False))
