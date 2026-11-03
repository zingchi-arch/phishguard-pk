"""Step 64: multi-signal urgent transfer / friend impersonation checks."""
import pytest
from fastapi.testclient import TestClient
from phishguard.api import app
from phishguard.deep_ai import _combine, redact_for_external
from phishguard.inference import analyze_message
from phishguard.pakistan_rules import assess_pakistani_context

USER_MESSAGE = ('ma noman bat krha hoo mujy arjunt 50000 jazzcash krdo '
                'is number pr 03409878555 mujhy bhot zroori kaam ha')


def test_exact_user_case_no_deep_ai_needed():
    result = analyze_message(USER_MESSAGE)
    assert result['verdict'] == 'Scam'
    assert result['risk_score'] >= 90
    assert result['safety_rule_floor'] >= 90
    assert 'PK_FRIEND_IMPERSONATION_URGENT_TRANSFER' in result['pakistan_rule_ids']
    assert result['sender_authentication'] == 'NOT_VERIFIED'
    assert not any('03409878555' in s for s in result['explanation'])
    assert any('personal identity' in s.lower() for s in result['explanation'])


@pytest.mark.parametrize('message', [
    'ma noman bat krha hoo mujy arjunt 50000 jazzcash krdo is number pr 03409878555 mujhy bhot zroori kaam ha',
    'Mein Ali baat kr rha hoon foran 50,000 EasyPaisa bhejdo is number par 03001234567',
    'This is Ahmed. Emergency! Send PKR 50000 to JazzCash 03331234567.',
    'Main Sana bat kar rhi hoo urgent 50k JazzCash krdo is number pe 03121234567',
    'میں علی بات کر رہا ہوں فوراً 50000 جاز کیش بھیجو اس نمبر پر 03001234567',
    'Main Saad bol rha hon, mjhe urgently 50 hazar jazzcash transfer karo, is number pr 03121234567',
])
def test_high_risk_language_and_amount_variants(message):
    result = analyze_message(message)
    assert result['verdict'] == 'Scam', message
    assert result['risk_score'] >= 88, message
    assert result['pakistan_rule_ids'], message


def test_no_identity_but_urgent_large_amount_phone_high_risk():
    r = analyze_message('urgent 50000 Jazzcash krdo 03001234567 asap')
    assert r['verdict'] == 'Scam'
    assert 'PK_URGENT_LARGE_PRIVATE_TRANSFER' in r['pakistan_rule_ids']


def test_large_amount_with_identity_but_no_phone_is_not_assumed_authentic():
    r=analyze_message('This is Ali, urgent send 50000 JazzCash please')
    assert r['verdict'] == 'Scam'
    assert 'PK_URGENT_CLAIMED_FRIEND_TRANSFER' in r['pakistan_rule_ids']


def test_smaller_urgent_transfer_is_caution_not_auto_scam():
    r = analyze_message('Ali here, 2500 JazzCash krdo is number par 03001234567 jaldi.')
    assert r['verdict'] in ('Safe','Suspicious')
    assert r['safety_rule_floor'] < 65


@pytest.mark.parametrize('message', [
    'Main Noman hun, kal milte hain.',
    'This is Ahmed. Can we talk tomorrow?',
    'UBL: Rs 50000 has been transferred to account 03001234567 successfully.',
    'JazzCash: 50000 Rs aap ko receive ho gaye hain. Kisi ko OTP share na karna.',
    'UBL: Agar madad chahiye to hamari 24/7 helpline 021-111-825-888 par call karein.',
])
def test_not_flagging_simple_identity_or_receipts_as_payment_demand(message):
    r = analyze_message(message)
    assert not any(x.startswith('PK_URGENT_') or x.startswith('PK_FRIEND_') or x.startswith('PK_LARGE_') for x in r['pakistan_rule_ids']), message
    assert r['safety_rule_floor'] < 65, message


def test_awareness_warning_does_not_fire_new_money_scam_rules():
    m = 'Fraud alert: if someone says main Ali bat kar raha hoon urgent 50000 jazzcash krdo 03001234567, do not send money.'
    ids = [r.rule_id for r in assess_pakistani_context(m)]
    assert not any(x.startswith(('PK_URGENT_', 'PK_FRIEND_', 'PK_LARGE_')) for x in ids)


def test_no_payment_command_does_not_trigger_even_with_urgent_amount_and_phone():
    m = 'Main Ali bol raha hoon 50000 ki transfer transaction 03001234567 par receive ho gayi hai, bohat urgent info hai.'
    ids = [r.rule_id for r in assess_pakistani_context(m)]
    assert not any(x.startswith(('PK_URGENT_', 'PK_FRIEND_', 'PK_LARGE_')) for x in ids)


def test_deep_ai_cannot_mark_explicit_high_risk_local_rule_safe():
    r = analyze_message(USER_MESSAGE)
    verdict, reason = _combine(r, {'verdict':'Safe', 'intent':'ordinary_notice'})
    assert verdict == 'Scam'
    assert 'high-risk' in reason


def test_phone_is_redacted_for_external_ai():
    s = redact_for_external(USER_MESSAGE)
    assert '03409878555' not in s
    assert '[PHONE REDACTED]' in s


def test_api_and_health_release_gate():
    client = TestClient(app)
    r = client.post('/analyze', json={'message':USER_MESSAGE})
    assert r.status_code == 200
    assert r.json()['verdict'] == 'Scam'
    health = client.get('/health').json()
    assert health['version'] == '2.5.0'
    assert health['payment_fraud_release_id'] == 'step64-urgent-personal-transfer-v1'
