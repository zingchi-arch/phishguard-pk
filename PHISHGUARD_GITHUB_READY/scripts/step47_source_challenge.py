"""Step47: honest 100-record SOURCE-LABEL proxy evaluation (NOT final accuracy).

Run:
  python scripts/step47_source_challenge.py --input /private/step41_combined.csv \
      --out /private/step47_proxy

The source records below have NOT been individually authenticated or human-reviewed.
This only measures agreement with available source categories on a 100-record
sample of Step41's source-designated TEST partition. It cannot prove this sample
was absent from all model-development data; the original development CSV is
missing from the repository snapshot. Never label results independent.
No external URLs are fetched, no private messages are exported in the report.
"""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_recall_fscore_support

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from phishguard.inference import analyze_message

COUNTS={
    ('English/Latin (PK corpus estimate)','Fraud'):24,
    ('English/Latin (PK corpus estimate)','Normal'):30,
    ('Roman Urdu','Fraud'):18,
    ('Roman Urdu','Normal'):25,
    ('Urdu script','Normal'):3,
}
N_TOTAL=sum(COUNTS.values())
assert N_TOTAL==100
REQUIRED=('record_id','message','language','source_label','research_category',
          'source','source_url','individually_verified','final_training_approved',
          'synthetic','cluster_id','split')


def choose_proxy_rows(path:Path):
    raw=pd.read_csv(path,dtype=str,keep_default_na=False,encoding='utf-8-sig')
    missing=[c for c in REQUIRED if c not in raw.columns]
    if missing:raise ValueError('Required source fields missing: '+', '.join(missing))
    if raw.record_id.duplicated().any():
        raise ValueError('Duplicate source record identifiers.')
    if not raw.synthetic.eq('NO').all():
        raise ValueError('Synthetic data is not permitted in this SOURCE-LABEL proxy.')
    if not raw.individually_verified.eq('NO').all() or not raw.final_training_approved.eq('NO').all():
        raise ValueError('This script is designed only for UNVERIFIED Step41 source candidates.')
    if raw[raw['split'].eq('test')].empty:
        raise ValueError('Source-marked test split missing.')
    selected=[]
    for (lang,cat),n in COUNTS.items():
        group=raw[(raw.split=='test')&(raw.language==lang)&(raw.research_category==cat)]
        if len(group)<n:raise ValueError(f'Not enough {lang}/{cat}: found {len(group)}, want {n}')
        selected.append(group.sample(n=n,random_state=2026).copy())
    df=pd.concat(selected,ignore_index=True)
    if len(df)!=100 or df.record_id.duplicated().any():raise ValueError('Proxy sample not distinct.')
    assert (df.split=='test').all()
    assert (df.final_training_approved=='NO').all()
    assert (df.individually_verified=='NO').all()
    # No review or official sender validation is being inferred.
    return df


def run_proxy(df:pd.DataFrame,predict=analyze_message):
    if len(df)!=100:raise ValueError('This challenge is fixed to 100 source-labelled candidates.')
    records=[]
    for row in df.itertuples(index=False):
        obj=predict(row.message)
        predicted=str(obj['verdict'])
        if predicted not in {'Safe','Suspicious','Scam'}:
            raise ValueError('Unexpected analyzer verdict: '+predicted)
        records.append(dict(record_id=row.record_id,
              sha256_message=hashlib.sha256(row.message.encode('utf-8')).hexdigest(),
              language=row.language, source_category=row.research_category,
              source=str(row.source), model_verdict=predicted,
              scam_alert=predicted in ('Suspicious','Scam'),
              strict_scam_prediction=predicted=='Scam'))
    pred=pd.DataFrame(records)
    # Source-category mapping is a research proxy, NOT human validation.
    y=df.research_category.tolist()
    category_pred=['Fraud' if v=='Scam' else 'Normal' if v=='Safe' else 'Review' for v in pred.model_verdict]
    strict_correct=sum(x==p for x,p in zip(y,category_pred))
    fraud_idx=[i for i,s in enumerate(y) if s=='Fraud']
    normal_idx=[i for i,s in enumerate(y) if s=='Normal']
    def fn_rate(idxs,key):
        return round(sum(bool(pred.iloc[i][key]) for i in idxs)/len(idxs),4) if idxs else None
    bylang={}
    for lang, subset in pred.groupby('language'):
        idx=subset.index
        fraud=[i for i in idx if y[i]=='Fraud']
        normal=[i for i in idx if y[i]=='Normal']
        bylang[lang]={
            'n':len(idx),'fraud_source_count':len(fraud),'normal_source_count':len(normal),
            'fraud_warning_recall_proxy':fn_rate(fraud,'scam_alert'),
            'normal_warning_rate_proxy':fn_rate(normal,'scam_alert'),
            'normal_strict_scam_false_positive_proxy':fn_rate(normal,'strict_scam_prediction'),
        }
    cm=confusion_matrix(y,category_pred,labels=['Normal','Fraud','Review']).tolist()
    result={
      'report_type':'SOURCE_LABEL_PROXY_NOT_FINAL_NOT_INDEPENDENT',
      'n':100,
      'strict_source_category_agreement_rate':round(strict_correct/100,4),
      'source_fraud_warning_recall_proxy':fn_rate(fraud_idx,'scam_alert'),
      'source_normal_warning_rate_proxy':fn_rate(normal_idx,'scam_alert'),
      'source_normal_false_scam_rate_proxy':fn_rate(normal_idx,'strict_scam_prediction'),
      'confusion_labels':['Normal','Fraud','Review'],
      'confusion_rows_source_columns_model':cm,
      'by_language':bylang,
      'data_handling':{'messages_exported':False,'only_sha256_message_and_source_record_id_in_private_detail':True},
      'evaluation_restrictions':{
        'independently_human_verified':False,
        'proof_of_real_message_origin':False,
        'synthetic_in_source_candidates':False,
        'source_marked_test_partition_only':True,
        'training_overlap_independently_ruled_out':False,
        'urdu_fraud_source_count':0,
        'three_class_accuracy_claim_allowed':False,
        'university_requirement_50_100_real_independent_test_met':False,
      },
      'warnings':[
        'Provisional source labels are NOT human adjudicated or sender authenticated.',
        'All three language families appear, but there are ZERO label-supported Urdu Fraud examples.',
        'Source-marked test status does not independently prove disjointness from all earlier development data.',
        'A Suspicious verdict is counted as a warning but neither correct strict Fraud nor strict Normal.',
        'No estimated population fraud accuracy, sensitivity, or specificity may be claimed from this proxy.',
      ]}
    return result,pred


def save_report(report:dict, detail:pd.DataFrame, out:Path):
    out.mkdir(parents=True,exist_ok=True)
    (out/'STEP47_PROXY_METRICS_NOT_FINAL.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    detail.to_csv(out/'STEP47_PROXY_HASHED_PREDICTIONS_PRIVATE.csv',index=False,encoding='utf-8-sig')
    langs='\n'.join(f"| {k} | {v['n']} | {v['fraud_source_count']} | {v['fraud_warning_recall_proxy']} | {v['normal_warning_rate_proxy']} |" for k,v in report['by_language'].items())
    md=f'''# Step 47: 100-Record Source-Label Proxy (not final evaluation)

**This is not a human-verified real-world accuracy study.** All inputs are from the Step41 source-designated test partition with original weak source categories. The actual training corpus is not completely available for leakage proof.

| Item | Result |
|---|---:|
| Source-labelled candidates screened | 100 |
| Strict Normal/Fraud agreement (Suspicious is neither) | {report['strict_source_category_agreement_rate']:.1%} |
| Source Fraud records triggering warning (Scam OR Suspicious) | {report['source_fraud_warning_recall_proxy']:.1%} |
| Source Normal records triggering warning | {report['source_normal_warning_rate_proxy']:.1%} |
| Source Normal records incorrectly called Scam | {report['source_normal_false_scam_rate_proxy']:.1%} |

| Source language group | N | Fraud source N | Fraud warning recall proxy | Normal warning rate proxy |
|---|---:|---:|---:|---:|
{langs}

**Critical gap:** Urdu script has only 3 `ham` examples in the source test partition, and **zero source-labelled Urdu Fraud** examples. Roman Urdu `0/1` labels use an unverified provisional mapping. English/Latin group has not been individually language-verified.

The analyzer was run without fetching URLs. Its `Safe` verdict does **not** authenticate a sender. This benchmark is for diagnosis only.

## Final independent evaluation status

**BLOCKED:** 50-100 authentic, independently reviewed and permissioned messages across Safe/Suspicious/Scam, English/Roman Urdu/Urdu, with model-development overlap excluded. Missing real-world inputs cannot be fabricated or replaced with teacher-generated synthetic messages.
'''
    (out/'STEP47_PROXY_SUMMARY_NOT_FINAL.md').write_text(md,encoding='utf-8')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--input',type=Path,required=True,help='Private Step41 combined SOURCE-LABEL candidates CSV')
    parser.add_argument('--out',type=Path,default=ROOT/'reports'/'step47_private')
    a=parser.parse_args()
    df=choose_proxy_rows(a.input)
    result,pred=run_proxy(df)
    save_report(result,pred,a.out)
    print(json.dumps(result,indent=2,ensure_ascii=False))

if __name__=='__main__':main()
