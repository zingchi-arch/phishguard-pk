"""Research-only URL-Phish 2026 supervised ML with registered-domain splits.

CLI: python scripts/step57_train_urlphish.py --data-zip PATH --output DIR

The source rows have non-verified provider labels, 0=benign, 1=phishing. It
never downloads URLs; string-only. Model is NOT enabled on the website.
"""
from __future__ import annotations
import argparse
import ctypes
import ctypes.util
import csv
import io
import json
import sys
import zipfile
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import GroupShuffleSplit

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from phishguard.url_ml_research import features_many, FEATURES
from phishguard.url_policy import assess_url

_lib=None
try:
    _lib=ctypes.CDLL(ctypes.util.find_library('psl') or 'libpsl.so.5')
    _lib.psl_builtin.restype=ctypes.c_void_p
    _lib.psl_registrable_domain.argtypes=[ctypes.c_void_p,ctypes.c_char_p]
    _lib.psl_registrable_domain.restype=ctypes.c_char_p
    _psl=_lib.psl_builtin()
except Exception:
    _lib=None


def registered_domain(url:str)->str:
    try:host=(urlsplit(url).hostname or '').lower().encode('idna').decode('ascii')
    except (ValueError,UnicodeError):return ''
    if not host:return ''
    if _lib:
        value=_lib.psl_registrable_domain(_psl,host.encode('ascii'))
        if value:return value.decode('ascii')
    return host # fallback must be flagged in report


def load_rows(zip_path:Path):
    with zipfile.ZipFile(zip_path) as z:
        match=[s for s in z.namelist() if s.endswith('/Dataset.csv') or s=='Dataset.csv']
        if len(match)!=1:raise ValueError('URL-Phish Dataset.csv not found uniquely')
        r=csv.DictReader(io.TextIOWrapper(z.open(match[0]),encoding='utf-8-sig'))
        if not {'url','label'}.issubset(r.fieldnames or []):raise ValueError('dataset schema mismatch')
        rows=[];duplicate=0;colliding=0;prior={}
        for row in r:
            url=row['url'].strip();label=row['label'].strip()
            if label not in ('0','1') or not (7<=len(url)<=2000):continue
            if url in prior:
                duplicate+=1
                if prior[url]!=label:colliding+=1
                continue
            group=registered_domain(url)
            if not group:continue
            prior[url]=label
            rows.append((url,int(label),group))
    return rows,{'exact_duplicates_removed':duplicate,'conflicting_labels_seen':colliding}


def metrics(labels,scores,threshold):
    predictions=(scores>=threshold).astype(int)
    p,r,f,_=precision_recall_fscore_support(labels,predictions,average='binary',zero_division=0)
    cm=confusion_matrix(labels,predictions,labels=[0,1]).tolist()
    return {'n':len(labels),'confusion_true_0_benign_1_phishing':cm,
            'accuracy':round(float(accuracy_score(labels,predictions)),4),
            'phishing_precision':round(float(p),4),'phishing_recall':round(float(r),4),
            'phishing_f1':round(float(f),4),
            'benign_false_warning_rate':round(float(cm[0][1]/max(1,sum(cm[0]))),4)}


def choose_threshold(labels,scores):
    candidates=[]
    for t in np.arange(.35,.991,.05):
        m=metrics(labels,scores,float(t))
        if m['benign_false_warning_rate']<=.02:
            candidates.append((m['phishing_recall'],m['phishing_f1'],float(t)))
    return max(candidates)[2] if candidates else 0.99


def run(data_zip:Path,out:Path):
    if _lib is None:raise RuntimeError('libpsl unavailable: registered-domain leakage audit required')
    out.mkdir(parents=True,exist_ok=True)
    rows,clean=load_rows(data_zip)
    urls=np.asarray([r[0] for r in rows]);labels=np.asarray([r[1] for r in rows]);groups=np.asarray([r[2] for r in rows])
    train_idx,hold_idx=next(GroupShuffleSplit(n_splits=1,train_size=.7,random_state=20261103).split(urls,labels,groups))
    val_rel,test_rel=next(GroupShuffleSplit(n_splits=1,train_size=.5,random_state=20261104).split(hold_idx,labels[hold_idx],groups[hold_idx]))
    val_idx=hold_idx[val_rel];test_idx=hold_idx[test_rel]
    assert not set(groups[train_idx])&set(groups[val_idx])
    assert not set(groups[train_idx])&set(groups[test_idx])
    assert not set(groups[val_idx])&set(groups[test_idx])
    assert all(len(set(labels[x]))==2 for x in (train_idx,val_idx,test_idx))
    X=features_many(urls.tolist())
    model=HistGradientBoostingClassifier(max_iter=145,max_depth=6,learning_rate=.07,
                                          min_samples_leaf=25,l2_regularization=3.,random_state=2026)
    model.fit(X[train_idx],labels[train_idx])
    val_scores=model.predict_proba(X[val_idx])[:,1]
    threshold=choose_threshold(labels[val_idx],val_scores)
    tm=metrics(labels[test_idx],model.predict_proba(X[test_idx])[:,1],threshold)
    # Fixed small reference set of legitimate-looking links includes DEEP paths.
    refpath=ROOT/'data'/'step44_reference_benign_30.csv'
    with refpath.open(encoding='utf-8-sig') as f:reference=[r['url'] for r in csv.DictReader(f)]
    ref_scores=model.predict_proba(features_many(reference))[:,1]
    score_ref_count=int(sum(ref_scores>=threshold))
    # Frozen stress cases are probes only; NOT blindly validated benign websites.
    stress=[u.rstrip('/')+path for u in reference[:12] for path in ('/login','/account/settings','/help','/products/item-1')]
    stress_scores=model.predict_proba(features_many(stress))[:,1]
    s_count=int(sum(stress_scores>=threshold))
    result={'type':'STEP57_RESEARCH_ONLY_URLPHISH_2026','dataset_label_mapping':{'0':'benign','1':'phishing'},
            'license':'CC BY 4.0; URL-Phish Mendeley Data DOI 10.17632/65z9twcx3r.2',
            'source_label_counts':dict(Counter(map(int,labels))), 'rows':len(rows), 'cleaning':clean,
            'domain_grouping':'libpsl_registrable','split_counts':{'train':len(train_idx),'validation':len(val_idx),'test':len(test_idx)},
            'registered_domain_group_overlap':0,'threshold_from_validation_only':round(threshold,3),
            'heldout_same_source':tm,'reference_30_warning_count':score_ref_count,
            'constructed_deep_path_probes':len(stress),'constructed_deep_path_warnings':s_count,
            'external_openphish_live_metrics':'NOT_EVALUATED_NO_RAW_TEST_FEED_AVAILABLE',
            'external_tranco_2026_metrics':'NOT_EVALUATED_NO_RAW_TEST_FEED_AVAILABLE',
            'model_deployment_approved':False,'note':'Same-source URL-Phish group-heldout test does not prove current external URL accuracy. Reference and deep-link probes are not independently authenticated benign samples.'}
    (out/'RESEARCH_ONLY_RESULTS.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    joblib.dump({'model':model,'feature_names':FEATURES,'threshold':threshold,'approved':False},out/'RESEARCH_ONLY_urlphish_2026.joblib',compress=3)
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--data-zip',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(run(a.data_zip,a.output),indent=2))
