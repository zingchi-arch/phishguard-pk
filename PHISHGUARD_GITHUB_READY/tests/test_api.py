from fastapi.testclient import TestClient
from phishguard.api import app
from phishguard.inference import analyze_message
client=TestClient(app)

def test_health():
    r=client.get('/health');assert r.status_code==200 and r.json()['status']=='ok'

def test_bad_input():
    assert client.post('/analyze',json={'message':''}).status_code==422
    assert client.post('/analyze',json={'message':'x'*10001}).status_code==422

def test_three_language_samples():
    for msg in ['Your appointment is confirmed tomorrow.','Apka account band hai, foran OTP bhejein',
                'مبارک ہو آپ نے انعام جیتا، بینک تفصیلات بھیجیں']:
        r=client.post('/analyze',json={'message':msg})
        assert r.status_code==200
        j=r.json();assert j['verdict'] in ('Safe','Suspicious','Scam')
        assert 0<=j['risk_score']<=100
        assert 'language_detected' in j and len(j['explanation'])>0

def test_urdu_credential_request_flagged():
    x=analyze_message('مبارک ہو آپ نے انعام جیت لیا، اپنی بینک تفصیلات بھیجیں')
    assert x['verdict']=='Scam'

def test_safe_otp_notice_not_automatically_scam():
    x=analyze_message('Your JazzCash OTP is 123456. Do not share it with anyone.')
    assert x['safety_rule_floor']==0

def test_url_features_returned():
    x=analyze_message('Go to https://bit.ly/claim-bonus urgently')
    assert x['urls'] and x['url_risk_indicator'] is not None
