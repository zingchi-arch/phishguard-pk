"""Mocked, network-free Step60 integration tests, NOT accuracy validation."""
import json
from pathlib import Path
from fastapi.testclient import TestClient
import httpx
import pytest
from phishguard.api import app
from phishguard import deep_ai
from phishguard.inference import analyze_message

client = TestClient(app)
JAZZ = 'apka jazzcash account bngya ha mubarak ho apna pin ya otp ksi kay sath share na krna'
SCAM = 'HBL support: apna OTP humein bhejo warna account band hoga'
GOOD_AI = {'verdict': 'safe', 'intent': 'protective_warning', 'reason': 'A warning not to disclose an OTP.', 'evidence': ['Do not share OTP'], 'uncertain': False}
BAD_AI = {'verdict': 'scam', 'intent': 'credential_request', 'reason': 'Asks for a private OTP.', 'evidence': ['Send your OTP'], 'uncertain': False}


def test_public_local_stays_offline(monkeypatch):
    def boom(*a, **kw):
        raise AssertionError('No third party calls are allowed for /analyze')
    monkeypatch.setattr(deep_ai, '_request_groq', boom)
    res = client.post('/analyze', json={'message': JAZZ})
    assert res.status_code == 200
    assert res.json()['verdict'] == 'Safe'
    assert 'deep_ai' not in res.json()


def test_consent_required_even_if_key_configured(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY', 'test-only')
    monkeypatch.setattr(deep_ai, '_request_groq', lambda *a, **k: pytest.fail('Must not contact Groq'))
    for body in ({'message': JAZZ}, {'message': JAZZ, 'consent_external_processing': False}):
        res = client.post('/analyze/deep', json=body)
        assert res.status_code == 422


def test_missing_key_returns_accurate_local_fallback(monkeypatch):
    monkeypatch.delenv('GROQ_API_KEY', raising=False)
    monkeypatch.setattr(deep_ai, '_request_groq', lambda *a, **k: pytest.fail('Should not call Groq'))
    body = client.post('/analyze/deep', json={'message': JAZZ, 'consent_external_processing': True}).json()
    assert body['verdict'] == 'Safe' and body['analysis_mode'] == 'local_fallback'
    assert body['deep_ai']['status'] == 'not_configured'
    assert body['deep_ai']['release_id'] == deep_ai.DEEP_AI_RELEASE


def test_real_deep_path_mocked_remote_and_fusion(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY', 'test-only')
    found = {}
    def fake_request(redacted, local):
        found['message'] = redacted
        found['local'] = local
        return GOOD_AI
    monkeypatch.setattr(deep_ai, '_request_groq', fake_request)
    body = client.post('/analyze/deep', json={'message': JAZZ, 'consent_external_processing': True}).json()
    assert body['analysis_mode'] == 'local_plus_qwen'
    assert body['verdict'] == 'Safe'
    assert body['deep_ai']['status'] == 'complete'
    assert body['deep_ai']['remote_verdict'] == 'Safe'
    assert found['local']['verdict'] == 'Safe'
    assert found['message'] == JAZZ
    assert body['sender_authentication'] == 'NOT_VERIFIED'


def test_large_deep_input_and_normal_input_difference():
    sample = 'ordinary meeting ' * 140
    assert len(sample) > deep_ai.MAX_DEEP_CHARS
    deep = client.post('/analyze/deep', json={'message': sample, 'consent_external_processing': True})
    assert deep.status_code == 422
    local = client.post('/analyze', json={'message': sample})
    assert local.status_code == 200


@pytest.mark.parametrize('bad,code', [
    (deep_ai.DeepAIError('rate_limited'), 'rate_limited'),
    (deep_ai.DeepAIError('network_unavailable'), 'network_unavailable'),
    (deep_ai.DeepAIError('provider_error'), 'provider_error'),
    (deep_ai.DeepAIError('invalid_provider_response'), 'invalid_provider_response'),
])
def test_provider_errors_never_disguised_as_ai(monkeypatch, bad, code):
    monkeypatch.setenv('GROQ_API_KEY', 'test-only')
    def fail(*a, **k):
        raise bad
    monkeypatch.setattr(deep_ai, '_request_groq', fail)
    body=client.post('/analyze/deep', json={'message': JAZZ, 'consent_external_processing': True}).json()
    assert body['analysis_mode'] == 'local_fallback'
    assert body['deep_ai']['status'] == code
    assert 'remote_verdict' not in body['deep_ai']


def test_redacts_phone_urls_otp_emails_and_ids():
    original='https://fake-bank.example/login?otp=123456 send test.person@gmail.com and 03001234567, CNIC 12345-1234567-1, OTP 992211 and www.fake.pk/otp'
    red=deep_ai.redact_for_external(original)
    assert '123456' not in red
    assert '03001234567' not in red
    assert 'gmail.com' not in red
    assert 'fake-bank.example' not in red
    assert 'fake.pk' not in red
    assert '[LINK REDACTED]' in red and '[PHONE REDACTED]' in red


def test_untrusted_url_never_becomes_network_destination(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY', 'test-only')
    visited=[]
    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs.get('follow_redirects') is False
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def post(self, url, **kwargs):
            visited.append((url, kwargs))
            return httpx.Response(200, json={'choices':[{'message':{'content': json.dumps(GOOD_AI)}}]})
    monkeypatch.setattr(deep_ai.httpx, 'Client', FakeClient)
    local=analyze_message('your bank account was blocked visit https://evil.example/pin')
    x=deep_ai._request_groq(deep_ai.redact_for_external('hello https://evil.example/pin'),local)
    assert x['verdict']=='safe'
    assert len(visited)==1 and visited[0][0] == deep_ai.GROQ_ENDPOINT
    body=visited[0][1]['json']
    assert body['model'] == deep_ai.MODEL_ID
    assert body['reasoning_effort'] == 'medium' and body['reasoning_format']=='hidden'
    assert body['response_format']['json_schema']['strict'] is True
    assert 'evil.example' not in body['messages'][0]['content']
    assert visited[0][1]['headers']['Authorization'].startswith('Bearer ')


def test_ai_cannot_suppress_high_risk_local_rule():
    local = analyze_message(SCAM)
    assert local['verdict'] == 'Scam' and local['safety_rule_floor'] >= 65
    final, note=deep_ai._combine(local, deep_ai._validate_opinion(GOOD_AI))
    assert final=='Scam'
    assert 'indicators' in note


def test_model_disagreement_not_falsely_definitive():
    local=analyze_message(JAZZ)
    verdict,_=deep_ai._combine(local,deep_ai._validate_opinion(BAD_AI))
    assert verdict=='Suspicious'
    assert 45 <= deep_ai._aligned_score(local['risk_score'],verdict) < 65


def test_invalid_ai_payload_is_rejected():
    with pytest.raises(deep_ai.DeepAIError):
        deep_ai._validate_opinion({'verdict':'trusted','intent':'other','reason':'trust the sender','evidence':[],'uncertain':False})
    with pytest.raises(deep_ai.DeepAIError):
        deep_ai._validate_opinion({'verdict':'safe','intent':'ordinary_notice','reason':'','evidence':['ok']*100,'uncertain':False})


def test_health_reports_configuration_without_secret(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY', 'DO_NOT_EXPOSE_SECRET_123')
    health=client.get('/health').json()
    assert health['deep_ai_configured'] is True
    assert health['deep_ai_release_id']==deep_ai.DEEP_AI_RELEASE
    assert 'DO_NOT_EXPOSE_SECRET_123' not in json.dumps(health)
    status=client.get('/model-status').json()
    assert status['deep_ai_default']=='OFF_EXTERNAL_CONSENT_REQUIRED'
    assert 'DO_NOT_EXPOSE_SECRET_123' not in json.dumps(status)


def test_ui_has_opt_in_and_rendered_status_and_mobile_font():
    web=Path(__file__).resolve().parents[1]/'phishguard'/'web'
    html=(web/'index.html').read_text(encoding='utf-8')
    js=(web/'app.js').read_text(encoding='utf-8')
    css=(web/'styles.css').read_text(encoding='utf-8')
    assert 'id="deep-ai-optin" disabled' in html
    assert 'id="deep-ai-result"' in html
    assert '/analyze/deep' in js
    assert 'consent_external_processing:true' in js
    assert deep_ai.DEEP_AI_RELEASE in js
    assert 'font-size:16px' in css
    assert 'maximum-scale=1' not in html


def test_app_level_limit_falls_back_to_local(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY', 'test-only')
    monkeypatch.setattr(deep_ai, '_allow_remote_request', lambda: False)
    monkeypatch.setattr(deep_ai, '_request_groq', lambda *a, **k: pytest.fail('Do not call provider when rate limited'))
    body=client.post('/analyze/deep', json={'message': JAZZ, 'consent_external_processing': True}).json()
    assert body['analysis_mode']=='local_fallback'
    assert body['deep_ai']['status']=='app_rate_limited'


def test_per_process_quota_is_capped(monkeypatch):
    # Isolate mutable state from the other tests; do not check provider quotas here.
    monkeypatch.setattr(deep_ai, '_RECENT_CALLS', deep_ai.deque())
    monkeypatch.setattr(deep_ai, '_THROTTLE_DAY', None)
    monkeypatch.setattr(deep_ai, '_THROTTLE_DAY_COUNT', 0)
    assert all(deep_ai._allow_remote_request() for _ in range(12))
    assert deep_ai._allow_remote_request() is False
