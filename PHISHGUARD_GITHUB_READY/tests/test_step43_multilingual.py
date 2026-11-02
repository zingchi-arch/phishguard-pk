"""Human-authored QA test cases, NOT real SMS or independent metrics."""
import pytest
from phishguard.pakistan_rules import assess_pakistani_context
from phishguard.inference import analyze_message
from fastapi.testclient import TestClient
from phishguard.api import app

RISK=[
 ('BISP: Aapke 50000 approved. WhatsApp [PHONE_REMOVED] par rabta karein.','PK_BISP_REDIRECT'),
 ('آپ کو بی آئی ایس پی سے پچاس ہزار روپے مل گئے، واٹس ایپ پر رابطہ کریں','PK_BISP_REDIRECT'),
 ('بینظیر انکم سپورٹ پروگرام: آپ کے پچاس ہزار روپے منظور، اس نمبر پر رابطہ کریں','PK_BISP_REDIRECT'),
 ('Jeeto Pakistan, you won 3 tola gold! Call [PHONE_REMOVED] to claim.','PK_JEETO_CLAIM'),
 ('مبارک ہو جیتو پاکستان میں آپ نے دو تولہ سونا جیت لیا، اس نمبر پر رابطہ کریں','PK_JEETO_CLAIM'),
 ('HBL support: please send us your OTP to verify.','PK_BANK_SECRET_REQUEST'),
 ('HBL: Never share OTP. But send us your PIN for verification.','PK_BANK_SECRET_REQUEST'),
 ('Meezan: Apna OTP abhi batao taake account unlock ho.','PK_BANK_SECRET_REQUEST'),
 ('بینک سے پیغام: اپنا او ٹی پی ابھی بھیجیں','PK_BANK_SECRET_REQUEST'),
 ('FIA notice: Arrest warrant issued. Pay Rs 5000 today at https://example.invalid/pay','PK_GOV_THREAT_PAY'),
 ('ایف آئی اے مقدمہ درج، گرفتاری سے بچنے کے لئے فیس جمع کروائیں','PK_GOV_THREAT_PAY'),
 ('PSCA e-challan payment due, pay at https://fake.example.invalid/pay','PK_CHALLAN_LINK'),
 ('ای چالان کی رقم ادا کریں https://fake.example.invalid/pay','PK_CHALLAN_LINK'),
]

NO_RISK=[
 'Eid Mubarak! Hope you and your family are happy.',
 'Congratulations on your graduation! Details of the party at https://example.com/invite',
 'HBL: Your OTP is 431201. Do not share it with anyone.',
 'Bank statement sirf app se check karein, PIN kabhi share na karein.',
 'PSCA e-challan status available in official app, please check yourself.',
 'Dear Consumer, aap ka bijli ka bill 1000 PKR hai. Official bank app se pay kar sakte hain.',
 'Salary of 2500 PKR has been credited to your SadaPay account.',
 'آپ کو عید مبارک، ہم آپ کی خوشی کے لیے دعا گو ہیں',
 'آپ کا اکاؤنٹ اس ماہ فعال رہا، اپنا او ٹی پی کسی کو نہ بتائیں',
]

@pytest.mark.parametrize('message,rule_id',RISK)
def test_multilingual_patterns(message,rule_id):
    ids={x.rule_id for x in assess_pakistani_context(message)}
    assert rule_id in ids, (rule_id,ids)
    assert analyze_message(message)['verdict']=='Scam'

@pytest.mark.parametrize('message',NO_RISK)
def test_safe_context_does_not_trigger_pakistan_scam_rule(message):
    assert not assess_pakistani_context(message)


def test_sender_spoof_not_authenticated():
    r=analyze_message('BISP: aap ko 50000 rupay mile. Call [PHONE_REMOVED] to claim.',sender_id='8171')
    assert r['verdict']=='Scam' and r['sender_authentication']=='NOT_VERIFIED'


def test_live_api_multilingual_and_metadata():
    client=TestClient(app)
    for m,_ in RISK:
        r=client.post('/analyze',json={'message':m})
        assert r.status_code==200
        d=r.json()
        assert d['verdict']=='Scam' and d['sender_authentication']=='NOT_VERIFIED'


def test_no_false_safety_claim_when_link_looks_official():
    r=analyze_message('Your appointment info: https://github.com/example')
    assert 'verified' not in str(r.get('sender_authentication','')).lower() or r['sender_authentication']=='NOT_VERIFIED'


def test_urdu_plain_greeting_synthetic_false_alarm_fixed():
    m='آپ کو عید مبارک، ہم آپ کی خوشی کے لیے دعا گو ہیں'
    r=analyze_message(m)
    assert r['verdict']=='Safe'
    assert r['personal_greeting_guard_applied'] is True


def test_greeting_does_not_hide_prize_fraud():
    m='Eid Mubarak! Jeeto Pakistan prize jeet liya, call [PHONE_REMOVED] to claim gold.'
    r=analyze_message(m)
    assert r['personal_greeting_guard_applied'] is False
    assert r['verdict']=='Scam'


def test_greeting_does_not_hide_link():
    m='Eid Mubarak! Please login at https://x.example.invalid to get your money.'
    r=analyze_message(m)
    assert r['personal_greeting_guard_applied'] is False
