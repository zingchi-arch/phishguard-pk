"""Step45: validate explanation fidelity, scope, limits and test metadata gate."""
import numpy as np
from fastapi.testclient import TestClient
from phishguard.api import app
from phishguard.attributions import explain_text_deletions

client=TestClient(app)

class SimpleModel:
    classes_=np.array(['Safe','Scam','Suspicious'])
    def predict_proba(self, texts):
        rows=[]
        for text in texts:
            risk=0.9 if 'otp' in text.lower().split() else 0.1
            rows.append([1-risk,risk,0.0])
        return np.array(rows)


def test_deletion_is_model_based_and_deterministic():
    obj=explain_text_deletions(SimpleModel(),'send otp now')
    assert obj['method']=='local_token_deletion_NOT_SHAP_OR_LIME'
    assert obj['tokens_tested']==3
    assert obj['positive_evidence'][0]['token']=='otp'
    assert 79.0 < obj['positive_evidence'][0]['change_in_scam_model_score_points'] < 81.0
    assert obj['negative_evidence']==[]


def test_long_message_bound_and_sampling():
    obj=explain_text_deletions(SimpleModel(),'word '*24+'otp')
    assert obj['token_count']==25 and obj['tokens_tested']==16
    assert any(r['token']=='otp' for r in obj['positive_evidence'])


def test_explain_rejects_long_payload_without_running_model():
    response=client.post('/analyze/explain',json={'message':'x'*901})
    assert response.status_code==422


def test_optin_explanation_real_backend():
    text='Dear customer, urgent account verification: send OTP to our number now.'
    response=client.post('/analyze/explain',json={'message':text})
    assert response.status_code==200, response.text
    obj=response.json()
    assert obj['verdict'] in {'Safe','Suspicious','Scam'}
    assert obj['model_attribution']['method']=='local_token_deletion_NOT_SHAP_OR_LIME'
    assert obj['model_attribution']['tokens_tested']<=16
    assert obj['model_attribution']['score_explained'].endswith('_only')


def test_url_only_explanation_explicitly_not_applicable():
    response=client.post('/analyze/explain',json={'message':'https://github.com.evil.invalid/claim'})
    assert response.status_code==200
    obj=response.json()
    assert obj['model_attribution']['status']=='not_applicable_to_url_only'
    assert obj['verdict']=='Scam'


def test_normal_endpoint_not_slowed_by_explanation():
    r=client.post('/analyze',json={'message':'Your payment was received.'})
    assert r.status_code==200
    assert 'model_attribution' not in r.json()


def test_batch_endpoint_not_slowed_by_explanation():
    r=client.post('/analyze/batch',json={'messages':['Hi there']})
    assert r.status_code==200
    assert 'model_attribution' not in r.json()['results'][0]['result']


def test_review_gate_rejects_unverified_synthetic(tmp_path):
    import pandas as pd
    from scripts.step45_independent_test_gate import validate, REQUIRED
    rows=[]
    for i in range(50):
        row={k:'sample' for k in REQUIRED}
        row.update({'message':f'Message {i} for test','label':['Safe','Scam','Suspicious'][i%3],
                    'language':['English','Roman Urdu','Urdu'][i%3],
                    'verified_by_reviewer':'NO','source_type':'synthetic'})
        rows.append(row)
    f=tmp_path/'unverified.csv';d=tmp_path/'dev.csv'
    pd.DataFrame(rows).to_csv(f,index=False)
    pd.DataFrame({'message':['hello']}).to_csv(d,index=False)
    import pytest
    with pytest.raises(ValueError,match='independently checked'):
        validate(f,d)


def test_explain_multilingual_inputs():
    for message in ('Aap ko inaam mila, apna OTP bhej dein',
                    'آپ کو انعام ملا ہے، اپنا او ٹی پی ابھی بھیجیں'):
        response=client.post('/analyze/explain',json={'message':message})
        assert response.status_code == 200, response.text
        assert response.json()['model_attribution']['tokens_tested'] >= 4


def test_review_gate_rejects_unavailable_dev_corpus(tmp_path):
    import pandas as pd
    from scripts.step45_independent_test_gate import validate, REQUIRED
    rows=[]
    for i in range(50):
        r={k:'sample' for k in REQUIRED}
        r.update(message=f'Distinct review message number {i}',label=['Safe','Suspicious','Scam'][i%3],
                 language=['English','Roman Urdu','Urdu'][i%3],
                 verified_by_reviewer='YES',source_type='recipient_consent',
                 rights_or_consent='CONSENT',review_date='2026-11-02')
        rows.append(r)
    candidate=tmp_path/'declared.csv'
    pd.DataFrame(rows).to_csv(candidate,index=False)
    import pytest
    with pytest.raises(ValueError,match='Development corpus missing'):
        validate(candidate,tmp_path/'missing-development.csv')
