"""Step61 OpenRouter mock-only integration tests, NOT provider accuracy claims."""
import json
from pathlib import Path
import httpx
from fastapi.testclient import TestClient
import pytest
from phishguard.api import app
from phishguard import deep_ai
from phishguard.inference import analyze_message

client = TestClient(app)
JAZZ = 'apka jazzcash account bngya ha mubarak ho apna pin ya otp ksi kay sath share na krna'
GOOD = {'verdict': 'safe', 'intent': 'protective_warning', 'reason': 'Do not share an OTP.', 'evidence': ['Do not share'], 'uncertain': False}


def test_openrouter_preferred_over_groq_and_health_hides_keys(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY', 'private-groq')
    monkeypatch.setenv('OPENROUTER_API_KEY', 'private-openrouter')
    assert deep_ai.provider_config() == ('OpenRouter', 'openrouter/free')
    data = client.get('/health').json()
    assert data['version'] in ('2.3.0', '2.4.0')
    assert data['deep_ai_release_id'] == deep_ai.DEEP_AI_RELEASE
    assert data['deep_ai_provider'] == 'OpenRouter'
    assert data['deep_ai_configured'] is True
    assert 'private-openrouter' not in json.dumps(data)
    assert 'private-groq' not in json.dumps(data)
    status = client.get('/model-status').json()
    assert status['deep_ai_model'] == 'openrouter/free'
    assert 'private-openrouter' not in json.dumps(status)


def test_offline_requests_never_call_remote_when_key_configured(monkeypatch):
    monkeypatch.setenv('OPENROUTER_API_KEY', 'mocked-only')
    monkeypatch.setattr(deep_ai, '_request_openrouter', lambda *_a, **_k: pytest.fail('unexpected remote call'))
    assert client.post('/analyze', json={'message': JAZZ}).json()['verdict'] == 'Safe'
    assert client.post('/analyze/deep', json={'message': JAZZ}).status_code == 422
    assert client.post('/analyze/deep', json={'message': JAZZ, 'consent_external_processing': False}).status_code == 422


def test_deep_openrouter_uses_remote_opinion_only_after_consent(monkeypatch):
    monkeypatch.setenv('OPENROUTER_API_KEY', 'mocked-only')
    monkeypatch.setattr(deep_ai, '_allow_remote_request', lambda: True)
    seen = []
    def mock_openrouter(text, local):
        seen.append((text, local['verdict']))
        return GOOD
    monkeypatch.setattr(deep_ai, '_request_openrouter', mock_openrouter)
    monkeypatch.setattr(deep_ai, '_request_groq', lambda *_a, **_k: pytest.fail('Should prefer OpenRouter'))
    body = client.post('/analyze/deep', json={'message': JAZZ, 'consent_external_processing': True}).json()
    assert body['deep_ai']['status'] == 'complete'
    assert body['deep_ai']['external_provider'] == 'OpenRouter'
    assert body['analysis_mode'] == 'local_plus_external_ai'
    assert body['verdict'] == 'Safe'
    assert seen == [(JAZZ, 'Safe')]


def test_outbound_openrouter_hardcoded_url_and_redaction(monkeypatch):
    monkeypatch.setenv('OPENROUTER_API_KEY', 'never-real')
    called = []
    class FakeClient:
        def __init__(self, **kw):
            assert kw.get('follow_redirects') is False
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def post(self, url, **kwargs):
            called.append((url, kwargs))
            return httpx.Response(200, json={'choices': [{'message': {'content': json.dumps(GOOD)}}]})
    monkeypatch.setattr(deep_ai.httpx, 'Client', FakeClient)
    local = analyze_message('Please verify at https://bad.example/login')
    message = deep_ai.redact_for_external('Visit https://bad.example/login email a@b.com phone 03001234567')
    result = deep_ai._request_openrouter(message, local)
    assert result == GOOD
    url, kwargs = called[0]
    assert url == deep_ai.OPENROUTER_ENDPOINT
    assert url == 'https://openrouter.ai/api/v1/chat/completions'
    assert kwargs['json']['model'] == 'openrouter/free'
    assert kwargs['json']['response_format']['json_schema']['strict'] is True
    assert 'bad.example' not in kwargs['json']['messages'][0]['content']
    assert '03001234567' not in kwargs['json']['messages'][0]['content']
    assert kwargs['headers']['Authorization'] == 'Bearer never-real'
    assert len(called) == 1


@pytest.mark.parametrize('status,expected', [(429, 'rate_limited'), (401, 'credential_error'), (503, 'provider_error')])
def test_outbound_error_maps_without_leaking_response(monkeypatch, status, expected):
    monkeypatch.setenv('OPENROUTER_API_KEY', 'private')
    class FakeClient:
        def __init__(self, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def post(self, *args, **kw): return httpx.Response(status, text='private error message')
    monkeypatch.setattr(deep_ai.httpx, 'Client', FakeClient)
    with pytest.raises(deep_ai.DeepAIError) as exc:
        deep_ai._request_openrouter('hello', {})
    assert exc.value.status == expected
    assert 'private' not in str(exc.value)


def test_unconfigured_uses_local_and_groq_still_optional(monkeypatch):
    monkeypatch.delenv('OPENROUTER_API_KEY', raising=False)
    monkeypatch.delenv('GROQ_API_KEY', raising=False)
    assert deep_ai.provider_config() is None
    res = client.post('/analyze/deep', json={'message': JAZZ, 'consent_external_processing': True}).json()
    assert res['verdict'] == 'Safe'
    assert res['deep_ai']['status'] == 'not_configured'
    monkeypatch.setenv('GROQ_API_KEY', 'fake-groq')
    assert deep_ai.provider_config() == ('Groq', deep_ai.MODEL_ID)


def test_ui_label_does_not_promise_qwen_for_random_free_router():
    root = Path(__file__).resolve().parents[1] / 'phishguard' / 'web'
    html = (root / 'index.html').read_text(encoding='utf-8')
    js = (root / 'app.js').read_text(encoding='utf-8')
    assert '<strong>Deep AI</strong>' in html
    assert 'Qwen 27B second opinion' not in js
    assert deep_ai.DEEP_AI_RELEASE in js
    assert '/analyze/deep' in js
