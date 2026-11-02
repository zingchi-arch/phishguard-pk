"""Strict source-evidence gate for future 50-100 real-world independent SMS evaluation.

This script cannot authenticate a person's review or evidence independently.
It rejects obvious missing metadata, synthetic examples, exact duplicates,
and near-duplicates against a supplied development corpus. If usable, it
runs the CURRENT analyzer once per message and writes a private report.

Required CSV fields:
  message,label,language,source,source_type,source_url_or_document,
  independent_reviewer_id,review_date,rights_or_consent,verified_by_reviewer

Run only after independently labelled genuine evidence is gathered:
 python scripts/step45_independent_test_gate.py --input new_real_sms.csv \\
   --development data/development_dataset.csv
"""
from __future__ import annotations
import argparse
import json
import re
import sys
from pathlib import Path
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from phishguard.preprocessing import normalize_message
from phishguard.inference import analyze_message

CLASSES=('Safe','Suspicious','Scam')
LANGUAGES=('English','Roman Urdu','Urdu')
VALID_SOURCES=('recipient_consent','published_public_message','institutional_case_report')
VALID_RIGHTS=('CONSENT','PUBLIC_SOURCE_WITH_CITATION','LICENSED_DATA')
REQUIRED=('message','label','language','source','source_type','source_url_or_document',
          'independent_reviewer_id','review_date','rights_or_consent','verified_by_reviewer')
SYNTHETIC=re.compile(r'\b(?:synthetic|generated|template|fabricated|ai-generated|illustrative|simulation)\b',re.I)


def validate(input_csv:Path,development_csv:Path,similarity_max=0.9):
    """Validate metadata and leakage. Status means gate passed, not evidence authenticated."""
    df=pd.read_csv(input_csv,dtype=str,keep_default_na=False,encoding='utf-8-sig')
    if any(k not in df.columns for k in REQUIRED):
        raise ValueError('Missing columns: '+', '.join(k for k in REQUIRED if k not in df.columns))
    if not 50 <= len(df) <= 100:
        raise ValueError('Independent holdout must have 50-100 records.')
    if df[list(REQUIRED)].apply(lambda x:x.astype(str).str.strip().eq('')).any().any():
        raise ValueError('Missing required message, label, reviewer or provenance details.')
    if not df['label'].isin(CLASSES).all() or not df['language'].isin(LANGUAGES).all():
        raise ValueError('Only three exact language and label names are accepted.')
    if not set(CLASSES).issubset(set(df.label)) or not set(LANGUAGES).issubset(set(df.language)):
        raise ValueError('Need at least one independently reviewed example for each language and class.')
    if not df['verified_by_reviewer'].str.upper().eq('YES').all():
        raise ValueError('Every record must have independently checked evidence (YES).')
    if df[list(('source_type','rights_or_consent','source'))].apply(lambda s:s.str.contains(SYNTHETIC)).any().any():
        raise ValueError('Synthetic/template-generated data must not enter the real-world test.')
    if not df.source_type.isin(VALID_SOURCES).all():
        raise ValueError('source_type must have a documented genuine evidence category.')
    if not df.rights_or_consent.isin(VALID_RIGHTS).all():
        raise ValueError('rights_or_consent must document permission or a citable public source.')
    try:
        dates=pd.to_datetime(df.review_date,format='%Y-%m-%d',errors='raise')
    except (ValueError,TypeError) as exc:
        raise ValueError('Review dates must be YYYY-MM-DD.') from exc
    if not development_csv.is_file():
        raise ValueError('Development corpus missing. A leakage-free final test cannot be claimed.')
    dev=pd.read_csv(development_csv,dtype=str,keep_default_na=False,encoding='utf-8-sig')
    if 'message' not in dev.columns:
        raise ValueError('Development CSV must have a message column.')
    texts=df.message.astype(str).tolist()
    devtexts=dev.message.astype(str).tolist()
    testnorm=[normalize_message(x) for x in texts]
    devnorm=set(normalize_message(x) for x in devtexts)
    if len(set(testnorm)) != len(testnorm):
        raise ValueError('Exact or normalization-equivalent duplicate test SMS.')
    if any(x in devnorm for x in testnorm):
        raise ValueError('Holdout overlaps the development corpus after normalization.')
    # Gate similarity without storing submitted content in artifact logs.
    vectorizer=TfidfVectorizer(analyzer='char_wb',ngram_range=(3,5),min_df=1,max_features=25000)
    alltexts=devtexts+texts
    V=vectorizer.fit_transform(alltexts)
    n=len(devtexts)
    within=linear_kernel(V[n:],V[n:])
    import numpy as np
    np.fill_diagonal(within,0)
    max_test_sim=float(within.max())
    max_dev_sim=float(linear_kernel(V[n:],V[:n]).max()) if n else 0.0
    if max_test_sim>=similarity_max or max_dev_sim>=similarity_max:
        raise ValueError(f'Possible template leakage. Highest similarity {max(max_test_sim,max_dev_sim):.3f} >= {similarity_max}. Review independently.')
    diagnostics={'n':len(df), 'languages':df.language.value_counts().to_dict(),
                 'labels':df.label.value_counts().to_dict(),
                 'test_internal_max_similarity':round(max_test_sim,4),
                 'test_vs_dev_max_similarity':round(max_dev_sim,4),
                 'claim':'Metadata/leakage gate passed. Does NOT authenticate claimed human review or consent.'}
    return df,diagnostics


def main(input_csv:Path,development_csv:Path,output_dir:Path,similarity_max=0.9):
    df,diagnostics=validate(input_csv,development_csv,similarity_max)
    output_dir.mkdir(parents=True,exist_ok=True)
    preds=[analyze_message(m) for m in df.message]
    df=df.copy()
    df['model_predicted_verdict']=[x['verdict'] for x in preds]
    df['uncalibrated_risk_indicator']=[x['risk_score'] for x in preds]
    metrics={'gate':diagnostics,'accuracy':float(accuracy_score(df.label,df.model_predicted_verdict)),
        'confusion_order':CLASSES,
        'confusion_matrix':confusion_matrix(df.label,df.model_predicted_verdict,labels=CLASSES).tolist(),
        'classification_report':classification_report(df.label,df.model_predicted_verdict,
                                                     labels=CLASSES,output_dict=True,zero_division=0),
        'per_language':{lang:{'n':len(sub), 'accuracy':float(accuracy_score(sub.label,sub.model_predicted_verdict))}
                        for lang,sub in df.groupby('language')},
        'warning':'Performance ONLY on this independent reviewer-declared holdout. Claims and consent are not verified by the script; no population-level guarantee.'}
    (output_dir/'independent_test_metrics.json').write_text(json.dumps(metrics,indent=2,ensure_ascii=False),encoding='utf-8')
    df.to_csv(output_dir/'PRIVATE_holdout_predictions.csv',index=False,encoding='utf-8-sig')
    return metrics


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--development',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=Path.home()/'phishguard_step45_private_eval')
    parser.add_argument('--similarity-max',type=float,default=0.9)
    a=parser.parse_args()
    print(json.dumps(main(a.input,a.development,a.output,a.similarity_max),indent=2))
