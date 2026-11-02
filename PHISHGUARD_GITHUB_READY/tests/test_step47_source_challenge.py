"""Step47 provenance-guard and calculation checks on mock-only fixtures."""
import pandas as pd
import pytest
from scripts.step47_source_challenge import COUNTS,choose_proxy_rows,run_proxy


def fixture_source_rows():
    rows=[]
    for (lang,cat),n in COUNTS.items():
        for i in range(n+2):
            rows.append({'record_id':f'X-{len(rows):05d}', 'message':f'{lang} {cat} sample {i}',
                         'language':lang,'source_label':'test','research_category':cat,
                         'source':'mock', 'source_url':'https://example.org',
                         'individually_verified':'NO','final_training_approved':'NO','synthetic':'NO',
                         'cluster_id':f'C-{len(rows)}','split':'test'})
    return pd.DataFrame(rows)


def test_source_proxy_only_100_and_unverified(tmp_path):
    d=fixture_source_rows()
    path=tmp_path/'source.csv';d.to_csv(path,index=False)
    sub=choose_proxy_rows(path)
    assert len(sub)==100
    assert sub.synthetic.eq('NO').all()
    assert sub.individually_verified.eq('NO').all()


def test_reject_synthetic_and_missing_review_status(tmp_path):
    d=fixture_source_rows(); d.loc[0,'synthetic']='YES'
    path=tmp_path/'source.csv'; d.to_csv(path,index=False)
    with pytest.raises(ValueError,match='Synthetic'):choose_proxy_rows(path)


def test_correct_proxy_warning_math_and_never_independent(tmp_path):
    d=fixture_source_rows();path=tmp_path/'source.csv';d.to_csv(path,index=False)
    sub=choose_proxy_rows(path)
    def fake_predict(message):
        return {'verdict':'Scam' if 'Fraud' in message else 'Safe'}
    report,preds=run_proxy(sub,predict=fake_predict)
    assert len(preds)==100
    assert report['strict_source_category_agreement_rate']==1.0
    assert report['source_fraud_warning_recall_proxy']==1.0
    assert report['source_normal_warning_rate_proxy']==0.0
    assert not report['evaluation_restrictions']['university_requirement_50_100_real_independent_test_met']
    assert report['by_language']['Urdu script']['fraud_source_count']==0
