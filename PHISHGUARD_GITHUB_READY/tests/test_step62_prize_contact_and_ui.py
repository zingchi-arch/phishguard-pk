"""Regression tests for Jeeto prize redirect, official sources and minimal UI."""
import re
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from phishguard.api import app
from phishguard.inference import analyze_message
from phishguard.pakistan_rules import assess_pakistani_context
from phishguard.official_contacts import (
    get_official_contact_context, crosscheck_known_official_page, _fetch_official_page,
)

client = TestClient(app)


def ids(s):
    return [x.rule_id for x in assess_pakistani_context(s)]


def test_exact_user_jeeto_phrase_is_scam():
    m = 'jeeto pakistan ki trf sy apko honda ki bike manzoor hoi ha humary watsapp pr rabta kry 032498230333'
    result = analyze_message(m)
    assert result['verdict'] == 'Scam'
    assert result['risk_score'] >= 90
    assert 'PK_JEETO_CLAIM' in result['pakistan_rule_ids']
    assert result['official_contact_reference']['verified_sender'] is False
    assert '032498230333' not in str(result['official_contact_reference'])


def test_roman_urdu_prize_variants():
    rows = [
        'Jeeto Pakistan se apko honda bike manzur ho gai hai, whatsapp 03249823033 par rabta kro',
        'Jeeto Pakistan apki gari approve ho gai, is number par call karein 03001234567',
        'Congratulations you have won a Honda motorcycle, WhatsApp 03331234567 to claim',
        'Aap ka inaam gold nikla hai, Whatsapp 03331234567 per rabta karein',
        'مبارک ہو موٹر سائیکل انعام میں مل گئی ہے، واٹس ایپ پر رابطہ کریں 03249823033',
    ]
    for m in rows:
        assert analyze_message(m)['verdict'] == 'Scam', m


def test_jeeto_claim_link_redirect_and_safe_advisory_not_flagged():
    assert 'PK_JEETO_CLAIM' in ids('Jeeto Pakistan me apko bike manzoor ho gai, claim at https://promo.example/win')
    awareness = 'Jeeto Pakistan prize scams are fake, do not contact 03249823033'
    assert 'PK_JEETO_CLAIM' not in ids(awareness)
    assert 'PK_PRIZE_REDIRECT' not in ids(awareness)


def test_account_safety_warning_stays_safe():
    msg = 'Apka JazzCash account ban gaya hai. Mubarak ho, PIN ya OTP kisi ke sath share na karna.'
    assert analyze_message(msg)['verdict'] == 'Safe'


def test_real_ubl_helpline_not_mislabeled_as_private_scam():
    msg = 'UBL: Agar madad chahiye to hamari 24/7 helpline 021-111-825-888 par call karein.'
    result = analyze_message(msg)
    assert result['verdict'] == 'Safe'
    assert not result['pakistan_rule_ids']
    assert result['official_contact_reference']['status'] == 'number_in_official_reference_not_sender_verified'


def test_mismatched_link_detected_without_fetching_it():
    info = get_official_contact_context('UBL security: use https://ubl-secure.example.net/login')
    assert info['status'] == 'unrecognised_claimed_link'
    assert info['verified_sender'] is False


def test_subdomain_boundary_and_no_private_number_in_response():
    bad = get_official_contact_context('Jeeto Pakistan won bike contact 03249823033 or https://arydigital.tv.evil.test/')
    assert bad['unrecognised_url_hosts'] == 1
    assert '03249823033' not in str(bad)
    good = get_official_contact_context('Jeeto Pakistan official site https://arydigital.tv/jeeto-pakistan/')
    assert good['official_domain_link_matches'] == 1
    assert good['verified_sender'] is False


def test_verify_endpoint_restricted_to_known_organizations(monkeypatch):
    with patch('phishguard.official_contacts._fetch_official_page', return_value=('official_page_retrieved','Contact 021-111-825-888')) as stub:
        res = client.post('/verify/contact',json={'message':'UBL official WhatsApp 021-111-825-888'}).json()
        assert res['online_status'] == 'number_appears_on_checked_page'
        assert res['verified_sender'] is False
        assert stub.call_count == 1
    with patch('phishguard.official_contacts._fetch_official_page') as stub:
        res = client.post('/verify/contact',json={'message':'Unknown inc. http://danger.example/p?x=123 call 03331234567'}).json()
        assert res['status'] == 'organization_not_in_limited_registry'
        stub.assert_not_called()


def test_online_absence_is_not_fraud_proof():
    with patch('phishguard.official_contacts._fetch_official_page', return_value=('official_page_retrieved','No contact here')):
        res=crosscheck_known_official_page('Jeeto Pakistan 03249823033')
        assert res['online_status'].endswith('INCONCLUSIVE')
        assert res['verified_sender'] is False


def test_network_unavailable_does_not_stop_local_analyzer():
    with patch('phishguard.official_contacts._fetch_official_page', return_value=('official_page_unavailable','')):
        res=client.post('/verify/contact',json={'message':'Jeeto Pakistan bike, whatsapp 03249823033'}).json()
        assert res['online_status'] == 'official_page_unavailable'
    local=client.post('/analyze',json={'message':'Jeeto Pakistan bike manzoor ho gai, whatsapp 03249823033'}).json()
    assert local['verdict']=='Scam'


def test_deep_ai_checkbox_is_minimal_and_consent_still_required():
    html=(Path(__file__).parents[1]/'phishguard/web/index.html').read_text()
    assert '<strong>Deep AI</strong>' in html
    assert 'Use Deep AI (free hosted model)' not in html
    assert 'deep-ai-availability' not in html
    assert 'consent_external_processing' in (Path(__file__).parents[1]/'phishguard/api.py').read_text()
    assert client.post('/analyze/deep', json={'message':'Hi','consent_external_processing':False}).status_code == 422


def test_health_release_and_source_endpoint():
    r=client.get('/health').json()
    assert r['version']=='2.5.0'
    assert r['contact_check_release_id']=='step62-prize-and-official-sources-v1'
    assert client.get('/').status_code==200
    assert client.get('/app.js').status_code==200


def test_official_jazzcash_whatsapp_number_is_not_automatically_scam():
    msg = 'JazzCash support: WhatsApp 0325-4444786. Never share your OTP.'
    result = analyze_message(msg)
    assert result['verdict'] == 'Safe'
    assert result['official_contact_reference']['status'] == 'number_in_official_reference_not_sender_verified'
    assert result['official_contact_reference']['verified_sender'] is False


def test_bisp_award_to_private_mobile_is_high_risk():
    msg = 'BISP: your payment approved. Call 03249823033 for your prize.'
    result = analyze_message(msg)
    assert result['verdict'] == 'Scam'
    assert 'PK_BISP_REDIRECT' in result['pakistan_rule_ids']


def test_deep_fusion_cannot_override_strong_prize_rule():
    from phishguard.deep_ai import _combine
    local = analyze_message('Jeeto Pakistan me apko honda bike manzoor hoi WhatsApp 03249823033')
    verdict, _ = _combine(local, {'verdict':'Safe','intent':'ordinary_notice'})
    assert local['safety_rule_floor'] >= 90
    assert verdict == 'Scam'
