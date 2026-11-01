"""Fetch the licensed UCI PhiUSIIL real URL dataset and prepare passive URLs.

Official source: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
PhiUSIIL labels: 1=legitimate, 0=phishing. This script converts those to
0=benign, 1=phishing for `scripts/train_real_urls.py`.

No suspicious URLs are visited. Dataset downloading itself requires internet.

Usage: pip install ucimlrepo
       python scripts/fetch_uci_url_data.py --max-rows 50000
       python scripts/train_real_urls.py --csv data/uci_phiusiil_url_labeled.csv
"""
from pathlib import Path
import argparse
import pandas as pd
ROOT=Path(__file__).resolve().parents[1]
SOURCE='UCI PhiUSIIL 2024 CC BY 4.0 (Prasad and Chandra)'

def fetch(limit=50000):
    from ucimlrepo import fetch_ucirepo
    dataset=fetch_ucirepo(id=967)
    x=dataset.data.features
    y=dataset.data.targets
    if 'URL' not in x.columns:
        raise ValueError('Unexpected UCI data schema, no URL column; stop and inspect source')
    labels=pd.to_numeric(y.iloc[:,0],errors='raise')
    if not set(labels.dropna().unique()).issubset({0,1}):
        raise ValueError('Unexpected labels; UCI source requires 1=legitimate and 0=phishing')
    frame=pd.DataFrame({'url':x['URL'].astype(str),'original_label':labels})
    frame=frame.dropna().drop_duplicates('url')
    # Source convention: 1 legitimate -> 0 benign; 0 phishing -> 1 phishing.
    frame['label']=(1-frame.original_label).astype(int)
    if limit and len(frame)>limit:
        n1=int(round(limit*(frame.label==1).mean()))
        frame=pd.concat([frame[frame.label.eq(1)].sample(n=n1,random_state=42),
                         frame[frame.label.eq(0)].sample(n=limit-n1,random_state=42)],ignore_index=True)
    frame['source']=SOURCE
    out=ROOT/'data/uci_phiusiil_url_labeled.csv';out.parent.mkdir(exist_ok=True)
    frame[['url','label','source']].to_csv(out,index=False,encoding='utf-8')
    print('Saved real labeled URLs:',len(frame),'phishing:',int(frame.label.sum()),'benign:',int((1-frame.label).sum()),'file:',out)
    return out
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--max-rows',type=int,default=50000);args=p.parse_args()
    fetch(args.max_rows)
