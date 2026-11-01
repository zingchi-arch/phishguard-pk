"""Create a TRACEABLE development-only training set, never claim verified labels.

Read-only inputs: data/candidate_inventory.csv (prior Step 19), data/synthetic_examples.csv.
Excluded: promotional SMS, UCI spam, unverified Urdu spam, and anything else ambiguous.
"""
from pathlib import Path
import pandas as pd
import re

ROOT=Path(__file__).resolve().parents[1]
INV=ROOT/'data/candidate_inventory.csv'
SYN=ROOT/'data/synthetic_examples.csv'
OUT=ROOT/'data/development_dataset.csv'

_PHONE=re.compile(r'(?<!\w)(?:\+?92[- ]?|0)3\d{2}[- ]?\d{3}[- ]?\d{4}(?!\w)')
_EMAIL=re.compile(r'(?i)\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b')

def mask(text):
    text=str(text).strip()
    return _EMAIL.sub('[EMAIL_REMOVED]',_PHONE.sub('[PHONE_REMOVED]',text))

def build():
    df=pd.read_csv(INV,dtype=str).fillna('')
    rows=[]
    mapping={
      ('Pakistan 2026 research SMS dataset','normal'):'Safe',
      ('Pakistan 2026 research SMS dataset','fraud'):'Scam',
      ('UCI SMS Spam','ham'):'Safe',
      ('Zenodo Roman Urdu phishing','0'):'Safe',
      ('Zenodo Roman Urdu phishing','1'):'Scam',
      ('Pak Spam Guard public dataset','ham'):'Safe',
    }
    for _,r in df.iterrows():
        key=(r['source'],r['source_label'].lower())
        label=mapping.get(key)
        if not label: continue
        message=mask(r['message'])
        if len(message)<7:continue
        language=r['language']
        if language.startswith('Latin script'): language='Unverified Latin'
        rows.append({
         'record_id':r['record_id'], 'message':message, 'language':language, 'label':label,
         'source':r['source'],'source_label':r['source_label'],
         'origin_type':'public_candidate_NOT_individually_reviewed',
         'training_approved':'NO','template_group':r['template_id'],
         'quality_note':'Provisional source mapping; NOT validated ground truth.'
        })
    sd=pd.read_csv(SYN,dtype=str).fillna('')
    for _,r in sd.iterrows():
        label=r['provisional_scenario_label'].strip().title()
        if label not in {'Safe','Suspicious','Scam'}:continue
        message=mask(r['message'])
        rows.append({'record_id':'SYN-'+r['id'],'message':message,'language':r['language'],
          'label':label, 'source':'Pakistani illustrated scenario '+r['scenario'],
          'source_label':r['provisional_scenario_label'], 'origin_type':'synthetic_illustration',
          'training_approved':'NO','template_group':'SYN-'+str(r['id']).split('-')[0],
          'quality_note':'Synthetic scenario; never count as real received message.'})
    out=pd.DataFrame(rows)
    out=out.drop_duplicates('message').reset_index(drop=True)
    assert set(out.label)=={'Safe','Suspicious','Scam'}
    assert {'Urdu','Roman Urdu','English'}.issubset(set(out.language))
    OUT.parent.mkdir(parents=True,exist_ok=True)
    out.to_csv(OUT,index=False,encoding='utf-8-sig')
    print('DEVELOPMENT ONLY (unvalidated source labels and synthetic samples)')
    print('Rows:',len(out),'\n',pd.crosstab(out.language,out.label))
    return out

if __name__=='__main__':build()
