"""User-reported contrastive, human-authored QA. NOT independent real-world accuracy."""
import pytest
from fastapi.testclient import TestClient
from phishguard.api import app
from phishguard.inference import analyze_message
from phishguard.message_intent import interpret_secret_intent

PROTECTIVE = [
    'apkey account ma 10000 transfer hogay kindly apna pin ksi kay sath bhi share na krna ;hbl',
    'apka jazzcash account bngya ha mubarak ho apna pin ya otp ksi kay sath share na krna',
    'HBL: Your OTP is 431201. Do not share it with anyone.',
    'Bank statement sirf app se check karein, PIN kabhi share na karein.',
    'Do not share your OTP or PIN with anyone.',
    'Never give your password to strangers.',
    'apna otp kisi ko na batao',
    'OTP kisi ko mat bhejo.',
    'PIN share nahi karna kisi ke sath.',
    'JazzCash customer, apni PIN kisi ko share na karein.',
    'OTP ko kisi bhi agent ko batana nahi chahiye; hifazat karein.',
    'اپنا او ٹی پی کسی کے ساتھ شیئر نہ کریں۔',
    'اپنا او ٹی پی کسی کو نہ بتائیں',
    'اپنا پن کوڈ کبھی مت بھیجیں۔',
]

SCAM = [
    'HBL support: please send us your OTP to verify.',
    'HBL: Never share OTP. But send us your PIN for verification.',
    'Never share OTP with anyone. But send it to 03001234567 for confirmation.',
    'JazzCash apna PIN humein share karo warna account block ho jayega.',
    'Mubarak ho! Apka 50000 rupay ka inaam nikla hai. Inaam lene ke liye apni bank details bhejein.',
    'اپنے بینک کا او ٹی پی فوراً ہمیں بھیجیں',
    'Never share OTP except with our account agent.',
    'Your OTP is 431201. Do not share it with anyone. Pay the fee at https://fake.example/claim',
    'Never share your PIN. Click here to verify: https://bank-security.example/verify-login',
    'Send your PIN now and never share it with anyone else.',
    'Never share OTP with strangers, give us your PIN please.',
]

@pytest.mark.parametrize('message',PROTECTIVE)
def test_security_advice_not_scam(message):
    result = analyze_message(message)
    assert result['verdict'] == 'Safe', (message, result)
    assert result['security_advice_detected'] and result['security_advice_guard_applied']
    assert not result['credential_request_detected']
    assert not any(x in result['explanation'] for x in ('Credential or verification request','Bank or benefit impersonation'))
    assert not result['highlighted_terms']

@pytest.mark.parametrize('message',SCAM)
def test_malicious_or_mixed_is_not_safe(message):
    result = analyze_message(message)
    assert result['verdict'] in ('Scam','Suspicious'), (message, result)
    assert not result['security_advice_guard_applied']


def test_mixed_credential_request_context():
    a=interpret_secret_intent('Never share OTP. But send it to our helpline.')
    assert a.protective_advice and a.unsafe_secret_request and not a.protective_only


def test_secure_api_message_and_no_private_logging():
    client=TestClient(app)
    msg=PROTECTIVE[1]
    result=client.post('/analyze',json={'message':msg})
    assert result.status_code==200
    assert result.json()['verdict']=='Safe'
    assert result.json()['security_advice_guard_applied'] is True
    assert msg not in str(result.json())
