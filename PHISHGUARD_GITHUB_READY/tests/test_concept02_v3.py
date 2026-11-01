from pathlib import Path
from fastapi.testclient import TestClient
from phishguard.api import app

client = TestClient(app)
WEB = Path(__file__).resolve().parents[1] / 'phishguard' / 'web'

def test_hero_static_lines_and_one_word():
    html = (WEB / 'index.html').read_text()
    assert 'hero-heading-line' in html
    assert 'id="typewriter"' in html
    assert 'hero-background-square.webp' in html
    assert 'hero-background-wide.webp' in (WEB / 'styles.css').read_text()

def test_pdf_route_and_button():
    html = client.get('/').text
    assert 'id="export-pdf"' in html
    assert '/pdf-report.js' in html
    assert 'PhishGuardPDF' in client.get('/pdf-report.js').text

def test_background_assets():
    for name in ('hero-background-wide.webp', 'hero-background-square.webp'):
        result=client.get('/assets/' + name)
        assert result.status_code == 200
        assert result.content[:4] == b'RIFF'

def test_api_not_replaced():
    response=client.post('/analyze', json={'message':'Hi, our meeting is tomorrow at noon.'})
    assert response.status_code == 200
    assert response.json()['verdict'] in {'Safe','Suspicious','Scam'}
