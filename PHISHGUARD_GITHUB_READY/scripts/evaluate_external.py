"""Run a true external-message evaluation, independent of development data.

Input CSV: message,label,language,reviewer,source. At least 50 distinct rows;
label must be Safe/Suspicious/Scam and reviewer/source nonempty. This script
rejects exact development corpus overlaps so copied demo examples cannot count.
"""
import argparse, hashlib, json, sys
from pathlib import Path
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from phishguard.inference import analyze_message
LABELS=['Safe','Suspicious','Scam']

def norm(s): return ' '.join(str(s).casefold().split())
def evaluate(csv):
    df=pd.read_csv(csv,dtype=str,keep_default_na=False)
    required={'message','label','language','reviewer','source'}
    if not required.issubset(df.columns):
        raise ValueError('Missing columns: '+str(required-set(df.columns)))
    for col in required:
        if (df[col].astype(str).str.strip()=='').any():raise ValueError('Missing '+col+' value(s)')
    if not df.label.isin(LABELS).all():raise ValueError('Labels must be Safe, Suspicious, Scam')
    if len(df)<50 or len(df)>1000:raise ValueError('Provide 50 to 1000 examples; university requirement suggests 50-100 new messages')
    df['normalized']=df.message.map(norm)
    if df.normalized.duplicated().any():raise ValueError('Repeated messages found in external test')
    dev=ROOT/'data/development_dataset.csv'
    if dev.exists():
        prior=set(pd.read_csv(dev,usecols=['message'],dtype=str)['message'].dropna().map(norm))
        overlap=df.normalized.isin(prior)
        if overlap.any():raise ValueError(f'{int(overlap.sum())} external messages overlap development data')
    df['prediction']=df.message.map(lambda m:analyze_message(m)['verdict'])
    df['risk_indicator']=df.message.map(lambda m:analyze_message(m)['risk_score'])
    output=ROOT/'reports/external_evaluation';output.mkdir(parents=True,exist_ok=True)
    df.drop(columns=['normalized']).to_csv(output/'predictions.csv',index=False)
    metrics={'n':len(df),'accuracy':float(accuracy_score(df.label,df.prediction)),
             'classification_report':classification_report(df.label,df.prediction,labels=LABELS,output_dict=True,zero_division=0),
             'confusion_matrix':confusion_matrix(df.label,df.prediction,labels=LABELS).tolist(),
             'per_language':{k:{'n':len(g),'accuracy':float(accuracy_score(g.label,g.prediction))} for k,g in df.groupby('language')},
             'note':'Metrics measure this independently sourced review set, not all future scams.'}
    (output/'metrics.json').write_text(json.dumps(metrics,indent=2),encoding='utf-8')
    df[df.label!=df.prediction].drop(columns=['normalized']).to_csv(output/'errors.csv',index=False)
    print('External evaluation complete:',len(df),'examples, accuracy',round(metrics['accuracy'],3))
    return metrics
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--csv',required=True,type=Path);a=p.parse_args();evaluate(a.csv)
