"""Step 44 QA test examples, not independent live threat intelligence labels."""
from pathlib import Path
import csv
import pytest
from fastapi.testclient import TestClient
from phishguard.api import app
from phishguard.inference import analyze_message, Analyzer
from phishguard.url_policy import assess_url

SAFE_EXAMPLES = [
    'https://github.com/openai',
    'https://github.com/python/cpython/issues/123',
    'https://en.wikipedia.org/wiki/Computer_security',
    'https://docs.python.org/3/library/urllib.parse.html',
    'https://developer.mozilla.org/en-US/docs/Web/JavaScript',
    'https://pypi.org/project/fastapi/',
    'https://www.youtube.com/watch?v=12345678',
    'https://www.reddit.com/r/python/',
    'https://example.org/notes',
    'https://www.sbp.org.pk/',
    'https://8171.bisp.gov.pk/',
    'https://www.jazzcash.com.pk/contact-us/',
    'https://www.meezanbank.com/contact-us/',
    'https://www.bankalfalah.com/contact-us/',
    'https://www.hbl.com/',
]
DECEPTIVE_QA_EXAMPLES = [
    'https://github.com.evil.invalid/login',
    'https://www.github.com.evil.invalid/security',
    'https://bisp.gov.pk.fraud.invalid/claim',
    'https://8171.bisp.gov.pk.evil.invalid/',
    'https://jazzcash.com.pk.fake.invalid/otp',
    'https://bankalfalah.com.fraud.invalid/account',
    'https://hbl.com.evil.invalid/verify',
    'https://meezanbank.com.evil.invalid/login',
    'https://fbr.gov.pk.false.invalid/claim',
    'https://google.com.evil.invalid/',
    'https://github.com@evil.invalid/login',
]

@pytest.mark.parametrize('url', SAFE_EXAMPLES)
def test_low_warning_on_reference_ordinary_links(url):
    x = assess_url(url)
    assert x.indicator < 45, (url, x)
    y = analyze_message(url)
    assert y['url_risk_indicator'] < 45 and y['verdict'] == 'Safe'
    assert y['sender_authentication'] == 'NOT_VERIFIED'

@pytest.mark.parametrize('url', DECEPTIVE_QA_EXAMPLES)
def test_deceptive_hostname_strongly_flagged(url):
    x = assess_url(url)
    assert x.indicator >= 75, (url, x)
    y = analyze_message(url)
    assert y['verdict'] == 'Scam' and y['url_structural_rule_floor'] >= 80
    assert y['url_only_input'] is True

@pytest.mark.parametrize('url', ['https://bit.ly/a1b2', 'https://tinyurl.com/fake2026'])
def test_shorteners_are_caution_not_confirmed_scam(url):
    x=assess_url(url)
    assert 45 <= x.indicator < 75
    assert analyze_message(url)['verdict'] == 'Suspicious'

@pytest.mark.parametrize('url', ['https://bisp-8171-prize.example/claim', 'https://jazzcash-verify.example/otp'])
def test_org_bait_is_not_dismissed_as_safe(url):
    assert assess_url(url).indicator >= 45


def test_http_only_not_automatically_a_scam():
    assert assess_url('http://example.com/notes').indicator < 45
    assert 45 <= assess_url('http://example.com/login').indicator < 75


def test_https_only_is_no_guarantee():
    r=analyze_message('https://github.com.evil.invalid/')
    assert r['verdict']=='Scam'
    assert r['urls'][0]['hostname_not_authenticated']=='github.com.evil.invalid'


def test_url_in_full_message_keeps_high_risk_floor():
    r=analyze_message('Please read: https://bisp.gov.pk.fraud.invalid/claim')
    assert r['verdict']=='Scam'


def test_api_never_opens_url_or_authenticates_sender(monkeypatch):
    # Network requests are not required by the offline analyzer; deliberately
    # not monkeypatching module imports, only checking API contract.
    response = TestClient(app).post('/analyze', json={'message':'https://hbl.com.evil.invalid/login'})
    assert response.status_code == 200
    data = response.json()
    assert data['verdict'] == 'Scam'
    assert data['sender_authentication'] == 'NOT_VERIFIED'
    assert data['url_model_status'] in ('offline_structural_rules_unvalidated', 'research_rf_diagnostic_not_in_decision')


def test_bad_port_never_crashes_analyzer():
    r=analyze_message('https://example.com:bad/login')
    assert r['urls'][0]['url_structural_status']=='invalid'
    assert r['verdict']=='Scam'


def test_research_rf_not_used_in_risk_decision():
    class FakeRF:
        def predict_proba(self, x): return [[0.01,0.99]]
    analyzer=Analyzer()
    analyzer.url_model=FakeRF()
    r=analyzer.analyze('https://www.python.org/')
    assert r['urls'][0]['real_data_rf_indicator']==99
    assert r['url_risk_indicator']<45 and r['verdict']=='Safe'
    assert r['url_model_status']=='research_rf_diagnostic_not_in_decision'
