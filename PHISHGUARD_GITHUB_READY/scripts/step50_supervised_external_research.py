"""Step 50: Dataset-separated phishing URL model research, NEVER deploy automatically.

Inputs: (a) 10k UCI PhiUSIIL 2024 URLs, labels 0=phishing 1=legitimate,
(b) fresh OpenPhish provider-labelled URLs, (c) dated Tranco domain homepage proxies.
Only passive URL string processing. No URLs in the datasets are requested, visited,
resolved, or dereferenced; only allowlisted publisher download operations happen
outside this file in the one-click Colab notebook.

External feed is OUT-OF-DOMAIN research evidence, not authenticated ground truth.
All external records in output are SHA-256 hashed. Exported model always named
RESEARCH_ONLY, never models/url_model_real.joblib.
"""
from __future__ import annotations
import argparse
import ctypes
import ctypes.util
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit
import numpy as np
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support, recall_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline

SAFE_EXAMPLES = [
 'https://github.com/','https://github.com/openai','https://en.wikipedia.org/wiki/Artificial_intelligence',
 'https://www.wikipedia.org','https://www.python.org','https://docs.python.org/3/',
 'https://www.microsoft.com','https://support.microsoft.com/','https://developer.mozilla.org/en-US/',
 'https://www.cloudflare.com','https://pypi.org/project/fastapi/','https://www.nasa.gov',
 'https://www.unicef.org','https://www.who.int','https://www.un.org','https://www.openai.com',
 'https://www.bbc.com','https://www.google.com','https://docs.google.com','https://www.apple.com',
 'https://www.amazon.com','https://www.khanacademy.org','https://www.ibm.com',
 'https://www.sbp.org.pk','https://www.fbr.gov.pk','https://www.irs.gov','https://www.gov.uk',
 'https://example.org/','https://www.youtube.com/','https://www.reddit.com/'
]

_psl_lib = None
_psl_context = None
try:
    _psl_lib = ctypes.CDLL(ctypes.util.find_library('psl') or 'libpsl.so.5')
    _psl_lib.psl_builtin.restype=ctypes.c_void_p
    _psl_lib.psl_registrable_domain.argtypes=[ctypes.c_void_p,ctypes.c_char_p]
    _psl_lib.psl_registrable_domain.restype=ctypes.c_char_p
    _psl_context=_psl_lib.psl_builtin()
except Exception:
    _psl_lib=None


def host_of(url:str)->str:
    try:
        p=urlsplit(url if re.match(r'^https?://',url,re.I) else 'http://'+url)
        h=(p.hostname or '').strip('.').lower().encode('idna').decode('ascii')
        return h if h and len(h)<254 and not any(c.isspace() for c in h) else ''
    except (ValueError,UnicodeError,TypeError):
        return ''


def registered_group(url:str)->str:
    host=host_of(url)
    if not host:return ''
    if _psl_lib is not None:
        try:
            res=_psl_lib.psl_registrable_domain(_psl_context,host.encode('ascii'))
            if res:return res.decode('ascii')
        except Exception:pass
    # Conservative fallback: exact hostname only; disclose limitation.
    return host


def site_group_quality()->str:
    return 'libpsl_registrable_domain' if _psl_lib is not None else 'EXACT_HOST_FALLBACK_NOT_REGISTRABLE'


def lexical_features(url:str)->list[float]:
    p=urlsplit(url if re.match(r'^https?://',url,re.I) else 'http://'+url)
    h=host_of(url); z=url.lower()
    digits=sum(ch.isdigit() for ch in z)
    return [min(len(z),3000),len(h),z.count('.'),z.count('-'),z.count('@'),digits,z.count('/'),
            z.count('?'),z.count('='),z.count('%'),z.count('&'),z.count('#'),
            len(p.path),len(p.query),len(h.split('.')),int(p.scheme=='https'),
            int('xn--' in h),int(bool(re.search(r'\b(?:verify|claim|login|bonus|reward|kyc|otp|prize)\b',z))),
            int(bool(re.search(r'\b(?:account|wallet|payment|update|password|security)\b',z)))]


def read_uci(path:Path)->tuple[pd.DataFrame,dict]:
    raw=pd.read_csv(path,dtype=str,keep_default_na=False)
    assert {'url','label_uci'}.issubset(raw.columns),'Expected URL and source-label columns'
    x=raw[['url','label_uci']].copy();x.url=x.url.str.strip()
    assert set(x.label_uci.unique())<= {'0','1'},'Unknown UCI label values'
    x['label']=1-x.label_uci.astype(int) # model: 1 phishing, 0 legitimate
    x=x[x.url.str.len().between(5,2000)].copy()
    # Contradictory labels for exact same URL are excluded, not arbitrarily resolved.
    conflicts=x.groupby('url').label.nunique();bad=set(conflicts[conflicts>1].index)
    x=x[~x.url.isin(bad)].drop_duplicates('url').copy()
    x['group']=x.url.map(registered_group)
    x=x[x.group.ne('')].reset_index(drop=True)
    return x,{'input_rows':int(len(raw)), 'usable_after_dedup':int(len(x)),
              'conflicting_url_values_removed':int(len(bad)),'grouping_quality':site_group_quality()}


def make_splits(df:pd.DataFrame):
    for seed in (2026,42,17,129,4902,6301,78):
        g=GroupShuffleSplit(n_splits=1,train_size=.70,random_state=seed)
        a,b=next(g.split(df,df.label,df.group));tr=df.iloc[a].copy();rest=df.iloc[b].copy()
        v,t=next(GroupShuffleSplit(n_splits=1,train_size=.5,random_state=seed+1).split(rest,rest.label,rest.group))
        val=rest.iloc[v].copy();te=rest.iloc[t].copy()
        if all(z.label.nunique()==2 and len(z)>=100 for z in (tr,val,te)):
            return tr,val,te
    raise ValueError('Unable to form viable group-disjoint splits')


def metrics(y,pr)->dict:
    p,r,f,_=precision_recall_fscore_support(y,pr,labels=[0,1],average='macro',zero_division=0)
    cm=confusion_matrix(y,pr,labels=[0,1]).tolist()
    return {'n':int(len(y)), 'accuracy':round(float(accuracy_score(y,pr)),4),
            'precision_macro':round(float(p),4),'recall_macro':round(float(r),4),
            'f1_macro':round(float(f),4),'phishing_recall':round(float(recall_score(y,pr,pos_label=1,zero_division=0)),4),
            'false_positive_rate':round(float(cm[0][1]/max(1,sum(cm[0]))),4),
            'confusion_matrix_labels_0_benign_1_phishing':cm}


def pick_threshold(y,probas)->tuple[float,dict]:
    # ALL threshold selection restricted to UCI validation; external sources never tune it.
    options=[]
    for threshold in np.arange(.25,.951,.05):
        t=round(float(threshold),2);m=metrics(y,probas>=t)
        options.append((m['f1_macro'],m['phishing_recall'],t,m))
    eligible=[x for x in options if x[3]['false_positive_rate']<=.05]
    if not eligible:
        return 0.5,{'reason':'No validation threshold achieved FPR<=5%; default 0.5 used','constraints_met':False}
    _,_,t,m=max(eligible,key=lambda x:(x[0],x[1]))
    return t,{'reason':'Validation-only macro F1 under FPR<=5% constraint','constraints_met':True,'selected_validation':m}


def _csv_hash_records(urls,probs,cohort,threshold):
    records=[]
    for url,pr in zip(urls,probs):
        records.append({'url_sha256':hashlib.sha256(url.encode()).hexdigest(),
          'hostname_sha256':hashlib.sha256(host_of(url).encode()).hexdigest(),
          'cohort':cohort,'model_score_not_calibrated':round(float(pr),4),
          'warning':bool(pr>=threshold)})
    return records


def train_and_evaluate(uci_file:Path,output:Path,openphish:list[str]|None=None,
                       tranco_domains:list[str]|None=None, baseline=None)->dict:
    output.mkdir(parents=True,exist_ok=True)
    d, audit=read_uci(uci_file)
    ext_ph=list(dict.fromkeys(openphish or []))
    ext_tr=list(dict.fromkeys(tranco_domains or []))
    # External samples and reference examples held out of training by registered group.
    ph_urls=[u for u in ext_ph if host_of(u)]
    tr_urls=['https://'+h.strip('/')+'/' for h in ext_tr if h and host_of('https://'+h)]
    ext_groups={registered_group(u) for u in ph_urls+tr_urls+SAFE_EXAMPLES}
    ext_groups.discard('')
    before=len(d)
    d=d[~d.group.isin(ext_groups)].copy()
    audit['excluded_external_or_reference_groups_rows']=int(before-len(d))
    assert len(d)>=1000 and d.label.nunique()==2, 'Insufficient data after source separation'
    train,val,test=make_splits(d)
    groups=[set(x.group) for x in (train,val,test)]
    assert not(groups[0]&groups[1] or groups[0]&groups[2] or groups[1]&groups[2])
    assert not((groups[0]|groups[1]|groups[2])&ext_groups)
    cv=Pipeline([('tfidf',TfidfVectorizer(analyzer='char',ngram_range=(3,5),min_df=2,max_features=65000,sublinear_tf=True)),
       ('classifier',SGDClassifier(loss='log_loss',alpha=2e-5,max_iter=1200,tol=1e-3,class_weight='balanced',random_state=2026))])
    cv.fit(train.url.astype(str).tolist(),train.label.to_numpy())
    cv_val=cv.predict_proba(val.url.astype(str).tolist())[:,list(cv.classes_).index(1)]
    lex=RandomForestClassifier(n_estimators=120,max_depth=15,min_samples_leaf=2,class_weight='balanced',n_jobs=-1,random_state=2026)
    xtr=np.asarray([lexical_features(u) for u in train.url],np.float32)
    xva=np.asarray([lexical_features(u) for u in val.url],np.float32)
    lex.fit(xtr,train.label.to_numpy())
    lex_val=lex.predict_proba(xva)[:,list(lex.classes_).index(1)]
    candidates=[]
    for name,model,vals in [('char_tfidf_linear',cv,cv_val),('lexical_random_forest',lex,lex_val)]:
        thresh,details=pick_threshold(val.label.to_numpy(),vals)
        m=metrics(val.label.to_numpy(),vals>=thresh)
        candidates.append({'name':name,'model':model,'threshold':thresh,
                           'val':m,'threshold_selection':details})
    winner=max(candidates,key=lambda x:(x['threshold_selection']['constraints_met'],x['val']['f1_macro']))
    def probability(model,urls):
        if model is cv:return model.predict_proba(list(urls))[:,list(model.classes_).index(1)]
        return model.predict_proba(np.asarray([lexical_features(u) for u in urls],np.float32))[:,list(model.classes_).index(1)]
    th=winner['threshold'];mdl=winner['model']
    ytest=test.label.to_numpy();p=probability(mdl,test.url.tolist());testm=metrics(ytest,p>=th)
    safe_proba=probability(mdl,SAFE_EXAMPLES)
    ext={}
    hashed=[]
    for name,urls in [('openphish_provider_label',ph_urls),('tranco_homepage_proxy',tr_urls)]:
        if not urls:
            ext[name]={'n':0,'status':'SOURCE_UNAVAILABLE_NOT_EVALUATED'};continue
        probs=probability(mdl,urls)
        ext[name]={'n':len(urls),'warnings_n':int(sum(probs>=th)),
                   'warnings_fraction':round(float(np.mean(probs>=th)),4),
                   'mean_uncalibrated_score':round(float(np.mean(probs)),4),
                   'status':'SOURCE_LABELLED_NOT_INDEPENDENTLY_VERIFIED' if name.startswith('openphish') else 'POPULAR_HOMEPAGE_PROXY_NOT_VERIFIED_SAFE'}
        hashed+=_csv_hash_records(urls,probs,name,th)
    if baseline:
        for name,urls in [('openphish_provider_label',ph_urls),('tranco_homepage_proxy',tr_urls)]:
            if urls:ext[name]['baseline_structural_45_warnings_n']=int(sum(baseline(u).indicator>=45 for u in urls))
    # Guard: predeclared diagnostic limits; still never auto-deploy even if pass.
    ph=ext.get('openphish_provider_label',{});leg=ext.get('tranco_homepage_proxy',{})
    stress=int(sum(safe_proba>=th))
    diagnostic_pass=bool(ph.get('n',0)>=100 and leg.get('n',0)>=100 and
           ph.get('warnings_fraction',0)>=.80 and leg.get('warnings_fraction',1)<=.05 and stress<=1 and
           testm['phishing_recall']>=.90 and testm['false_positive_rate']<=.05 and
           winner['threshold_selection']['constraints_met'] and site_group_quality()=='libpsl_registrable_domain')
    summary={'experiment':'STEP50_UCI_2024_TRAIN_FRESH_FEEDS_SEPARATE_RESEARCH',
      'data':audit, 'labels':'UCI source: 1 legitimate, 0 phishing; internal: 1 phishing, 0 legitimate',
      'split_rows':{k:int(len(v)) for k,v in [('train',train),('validation',val),('test',test)]},
      'split_registered_domain_overlap':0,'external_group_overlap_with_training':0,
      'model_candidates_validation':[{k:v for k,v in a.items() if k!='model'} for a in candidates],
      'winner':winner['name'],'threshold_selected_on_validation':th,
      'uci_heldout_source_label_metrics':testm,
      'external_source_diagnostics':ext,
      'legacy_30_reference_urls_warning_count':stress,
      'diagnostic_gate_pass':diagnostic_pass,
      'deployment_approved':False,
      'deployment_note':'NO DEPLOYMENT. Diagnostic gate alone is insufficient. Needs independent real-world and Pakistani URL validation.',
      'safety':'Only URL strings classified; no candidate URLs opened, resolved, or requested.',
      'risks':['UCI 2024 aged data and possible template/source artifacts',
               'Provider-labelled OpenPhish feed not individually verified',
               'Tranco popular domains are NOT authenticated legitimate URLs',
               'Homepage proxies omit legitimate deep links',
               'Scores are NOT calibrated probabilities or guarantees of safety']}
    (output/'STEP50_RESULTS.json').write_text(json.dumps(summary,indent=2,ensure_ascii=False),encoding='utf8')
    pd.DataFrame(hashed,columns=['url_sha256','hostname_sha256','cohort','model_score_not_calibrated','warning']).to_csv(output/'STEP50_EXTERNAL_HASHED_ONLY.csv',index=False)
    (output/'DO_NOT_DEPLOY.txt').write_text('RESEARCH ONLY: UCI 2024 labels and 2026 provider/proxy diagnostics are not independent real-world accuracy. NEVER upload model to live site.\n')
    joblib.dump({'model':mdl,'threshold':th,'model_type':winner['name'], 'label_mapping':{'0':'legitimate','1':'phishing'},
                 'deployment_approved':False},output/'STEP50_MODEL_RESEARCH_ONLY.joblib',compress=3)
    return summary

if __name__=='__main__':
    a=argparse.ArgumentParser()
    a.add_argument('--uci-file',type=Path,required=True)
    a.add_argument('--output',type=Path,required=True)
    a.add_argument('--openphish-file',type=Path)
    a.add_argument('--tranco-file',type=Path)
    args=a.parse_args()
    op=args.openphish_file.read_text().splitlines() if args.openphish_file else None
    td=args.tranco_file.read_text().splitlines() if args.tranco_file else None
    report=train_and_evaluate(args.uci_file,args.output,op,td)
    print(json.dumps({k:report[k] for k in ('winner','threshold_selected_on_validation','uci_heldout_source_label_metrics','external_source_diagnostics','legacy_30_reference_urls_warning_count','deployment_approved')},indent=2))
