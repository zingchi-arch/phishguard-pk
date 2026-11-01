"""Train an independently labeled real-URL Random Forest and measure a held-out set.

Usage:
    python scripts/train_real_urls.py --csv data/real_urls_labeled.csv

Source CSV must include url,label,source. Labels: 0/1, benign/phishing,
Safe/Scam. Do not fabricate real labels, and preserve source attribution.

Strict safety: features are lexical only, no URL is requested or opened.
"""
import argparse, json, sys
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support, classification_report
from sklearn.model_selection import GroupShuffleSplit
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from phishguard.urls import feature_vector, safe_hostname, FEATURE_NAMES

VALID={'benign':0,'safe':0,'legitimate':0,'0':0,'phishing':1,'phish':1,'scam':1,'malicious':1,'1':1}

def train(csv):
    df=pd.read_csv(csv,dtype=str,keep_default_na=False)
    if not {'url','label','source'}.issubset(df.columns):
        raise ValueError('Required columns: url, label, source')
    df=df[['url','label','source']].copy()
    df['url']=df.url.str.strip()
    df['label']=df.label.str.strip().str.lower().map(VALID)
    df=df[df.url.ne('') & df.source.str.strip().ne('') & df.label.notna()].drop_duplicates('url')
    df['host']=df.url.map(safe_hostname)
    df=df[df.host.ne('') & df.url.str.len().le(2000)]
    n=len(df)
    if n<200 or df.label.value_counts().min()<50 or df.host.nunique()<30:
        raise ValueError('Need >=200 distinct labeled URLs, >=50 per class and >=30 different hosts')
    # Exact same host may never appear in training and test. Stronger than row-level random split.
    groups=df.host
    split=GroupShuffleSplit(n_splits=1,train_size=.70,random_state=42)
    tr,rem=next(split.split(df,df.label,groups))
    train_df=df.iloc[tr];rem_df=df.iloc[rem]
    sub=GroupShuffleSplit(n_splits=1,train_size=.50,random_state=43)
    va,te=next(sub.split(rem_df,rem_df.label,rem_df.host))
    val_df=rem_df.iloc[va];test_df=rem_df.iloc[te]
    if any(part.label.nunique()<2 for part in [train_df,val_df,test_df]):
        raise ValueError('Both classes are required in train, validation and test; add more diverse domains')
    features=lambda d:np.asarray([feature_vector(x) for x in d.url],dtype=np.float32)
    xtrain=features(train_df);xval=features(val_df);xtest=features(test_df)
    models=[]
    for depth in [8,16,None]:
        model=RandomForestClassifier(n_estimators=200,max_depth=depth,random_state=42,
                          class_weight='balanced',min_samples_leaf=2,n_jobs=-1)
        model.fit(xtrain,train_df.label.astype(int))
        preds=model.predict(xval)
        _,_,f1,_=precision_recall_fscore_support(val_df.label.astype(int),preds,
                                                  average='macro',zero_division=0)
        models.append((f1,model,depth))
    _,winner,depth=max(models,key=lambda x:x[0])
    preds=winner.predict(xtest);truth=test_df.label.astype(int)
    prec,rec,f1,_=precision_recall_fscore_support(truth,preds,average='macro',zero_division=0)
    scores={'source_csv':str(csv),'source_counts':df.source.value_counts().to_dict(),
       'training_urls':len(train_df),'validation_urls':len(val_df),'test_urls':len(test_df),
       'train_hosts':int(train_df.host.nunique()),'test_hosts':int(test_df.host.nunique()),
       'host_overlap':len(set(train_df.host)&set(test_df.host)),
       'selected_depth':depth,'accuracy':float(accuracy_score(truth,preds)),
       'precision_macro':float(prec),'recall_macro':float(rec),'f1_macro':float(f1),
       'confusion_matrix':confusion_matrix(truth,preds,labels=[0,1]).tolist(),
       'feature_importance':dict(zip(FEATURE_NAMES,[float(v) for v in winner.feature_importances_])),
       'caution':'Real labeled data, but URL-only lexical features and domain-shift limit generalization.'}
    (ROOT/'models').mkdir(exist_ok=True);(ROOT/'reports').mkdir(exist_ok=True)
    joblib.dump(winner,ROOT/'models/url_model_real.joblib',compress=3)
    (ROOT/'reports/url_real_metrics.json').write_text(json.dumps(scores,indent=2),encoding='utf-8')
    test_df.assign(prediction=preds).to_csv(ROOT/'reports/url_real_holdout.csv',index=False)
    print('Saved real-data URL model. Test macro F1:',round(float(f1),4))
    return scores

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--csv',required=True,type=Path);args=p.parse_args()
    train(args.csv)
