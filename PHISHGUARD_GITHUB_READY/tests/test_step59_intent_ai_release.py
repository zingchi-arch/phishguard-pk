"""Release smoke and contrast checks. NOT an independent real-world evaluation."""
from fastapi.testclient import TestClient
from phishguard.api import app
from phishguard.inference import analyze_message
from phishguard.intent_ai import predict_message_intent, ENGINE_ID
from phishguard.message_intent import interpret_secret_intent
import pytest

SAFE = [
    'apka jazzcash accoutn bngya ha mubarak ho apna pin ya otp ksi kay sath share na krna',
    'apna otp kisi kay sath share nhe krna',
    'apni pin ksi ko share nah karen',
    'apna otp kisi k sath share nh krna',
    'Jazzcash customer, apna otp kisi ko bhi share na karo',
    'Your HBL account is ready, do not share your password with anyone.',
    'Never give your OTP to anyone, including our employees.',
    'Never share your bank PIN with others.',
    'Your new OTP is 123456. Do not share it with anyone.',
    'اپنا او ٹی پی کسی کے ساتھ شیئر نہ کریں۔',
    'آپ کا اکاؤنٹ بن گیا ہے، اپنا پن کوڈ کسی کو نہ بتائیں۔',
]
UNSAFE = [
    'apna otp hamein send kardo',
    'apna pin hme bata dein',
    'Jazzcash apna PIN humein share karo warna account block ho jayega.',
    'HBL support please send us your OTP to verify',
    'Never share OTP. But send it to our support chat.',
    'OTP kisi ko mat bhejna lekin humein send krdo',
    'Never share your OTP but send it to our agent now',
    'Your OTP is confidential except you must send it to our agent.',
    'اپنا او ٹی پی کسی کو نہ بتائیں، لیکن ہمیں فوراً بھیجیں۔',
]

@pytest.mark.parametrize('message', SAFE)
def test_safety_advice_safe(message):
    result=analyze_message(message)
    assert result['verdict']=='Safe', (message,result)
    assert result['security_advice_guard_applied']
    assert not result['credential_request_detected']
    assert result['engine_release']==ENGINE_ID
    assert result['intent_ai']['engine']==ENGINE_ID

@pytest.mark.parametrize('message', UNSAFE)
def test_request_or_mixed_warning_not_safe(message):
    result=analyze_message(message)
    assert result['verdict'] in ('Scam','Suspicious'), (message,result)
    assert not result['security_advice_guard_applied']

@pytest.mark.parametrize('message,expected', [
    ('apna otp kisi kay sath share nhe krna','protect'),
    ('apna pin hamein send kro','request'),
    ('Never share OTP but send it to our agent now','mixed'),
    ('Your wallet balance is 10000 rupees','other'),
])
def test_real_ml_predictor_runs(message,expected):
    p=predict_message_intent(message)
    assert p.label==expected and 0<p.score<1


def test_no_false_safety_on_payment_redirect():
    result=analyze_message('Never share OTP, click here to pay fee: https://fraud.example/verify')
    assert result['verdict']!='Safe'
    assert not result['security_advice_guard_applied']


def test_release_api_and_model_status():
    c=TestClient(app)
    health=c.get('/health').json()
    assert health['release_id']==ENGINE_ID and health['intent_ai_available']
    body=c.post('/analyze',json={'message':SAFE[0]}).json()
    assert body['verdict']=='Safe' and body['engine_release']==ENGINE_ID
    assert body['intent_ai']['validation'].startswith('DEVELOPMENT_')
    assert c.get('/model-status').json()['release_id']==ENGINE_ID


def test_frontend_has_real_backend_release_check():
    from pathlib import Path
    web=Path(__file__).resolve().parents[1]/'phishguard'/'web'
    js=(web/'app.js').read_text(encoding='utf-8')
    html=(web/'index.html').read_text(encoding='utf-8')
    assert "fetch('/health'" in js
    assert ENGINE_ID in js
    assert 'OLD BACKEND' in js
    assert 'id="engine-tag"' in html
    assert 'width=device-width' in html
    assert 'maximum-scale=1' not in html


def test_intent_ai_no_third_party_calls():
    import inspect
    from phishguard import intent_ai
    source=inspect.getsource(intent_ai)
    assert 'requests.' not in source
    assert 'http://' not in source and 'https://' not in source
    assert 'logger' not in source
