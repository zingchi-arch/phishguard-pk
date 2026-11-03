"""Step 53: user-supplied repository sync. CSS zoom fix + honest URL evidence."""
from pathlib import Path
from fastapi.testclient import TestClient
from phishguard.api import app
from phishguard.inference import analyze_message
import json
import re

ROOT=Path(__file__).resolve().parents[1]
WEB=ROOT/'phishguard'/'web'
client=TestClient(app)


def test_mobile_textarea_font_does_not_trigger_ios_safari_focus_zoom():
    s=(WEB/'styles.css').read_text()
    # The last 16px declaration overrides the older 13px mobile styling.
    assert '#message, #csv-file { font-size:16px; }' in s
    assert '.panel textarea, .batch-controls input[type="file"] { font-size:16px; touch-action:manipulation; }' in s
    html=(WEB/'index.html').read_text()
    viewport=re.search(r'<meta name="viewport" content="([^"]+)">',html)
    assert viewport is not None
    assert 'width=device-width' in viewport.group(1)
    assert 'user-scalable=no' not in viewport.group(1)
    assert 'maximum-scale=1' not in viewport.group(1)


def test_url_results_are_clearly_unverified_no_live_network_call():
    for url in ('https://github.com/', 'https://gov.pk.login.example.invalid'):
        x=analyze_message(url)
        assert x['url_only_input'] is True
        assert x['url_verification_status']=='NOT_VERIFIED_OFFLINE_ONLY'
        assert x['urls'][0]['url_authenticity']=='NOT_VERIFIED'
        assert any('NOT been verified' in line for line in x['explanation'])
    assert analyze_message('Hi, our meeting is at 3pm.')['url_verification_status']=='NO_URL_PROVIDED'


def test_research_endpoint_reflects_source_files_without_accuracy_claim():
    source=json.loads((ROOT/'evaluation/STEP50_EXTERNAL_RESEARCH_RESULTS.json').read_text())
    gate=json.loads((ROOT/'evaluation/STEP51_RELEASE_GATE_FAIL.json').read_text())
    assert gate['production_approved'] is False
    x=client.get('/research-status')
    assert x.status_code==200
    obj=x.json()
    op=source['external_source_diagnostics']['openphish_provider_label']
    tr=source['external_source_diagnostics']['tranco_homepage_proxy']
    assert obj['structural_openphish_warnings']==op['baseline_structural_45_warnings_n']
    assert obj['openphish_source_urls']==op['n']
    assert obj['tranco_popular_domains']==tr['n']
    assert obj['experimental_model_tranco_warnings']==tr['warnings_n']
    assert obj['supervised_url_model_deployed'] is False
    assert obj['real_world_independent_accuracy_verified'] is False


def test_new_site_features_available_and_research_not_claimed_shap():
    h=client.get('/').text
    for key in ('id="link-caution"','id="explain-model"','id="research-results"',
                'Links screened (offline)','id="model-evidence"'):
        assert key in h
    j=client.get('/app.js').text
    assert "post('/analyze/explain'" in j
    assert "fetch('/research-status'" in j
    assert "requestSequence" in j
    assert 'experimental' in h
    assert 'SHAP' not in h or 'NOT SHAP' in h


def test_unchanged_sms_and_url_scam_rule_behaviour():
    assert client.post('/analyze',json={'message':'Mubarak ho! Apka inaam nikla hai. Bank details bhejein.'}).json()['verdict']=='Scam'
    assert client.post('/analyze',json={'message':'https://bisp.gov.pk.evil.invalid/claim'}).json()['verdict']=='Scam'
    r=client.post('/analyze',json={'message':'https://github.com/python/cpython'})
    assert r.status_code==200
    assert r.json()['url_verification_status']=='NOT_VERIFIED_OFFLINE_ONLY'
