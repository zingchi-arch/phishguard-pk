from pathlib import Path
from fastapi.testclient import TestClient
from phishguard.api import app

client = TestClient(app)
WEB = Path(__file__).resolve().parents[1] / 'phishguard' / 'web'

def test_hero_has_same_layered_background_on_mobile_and_desktop():
    html = (WEB / 'index.html').read_text()
    css = (WEB / 'styles.css').read_text()
    js = (WEB / 'motion.js').read_text()
    assert 'before you click.' in html
    assert 'hero-visual' not in html
    assert 'id="typewriter"' not in html
    assert "shield-original-square.webp" in css
    assert "shield-original-wide.webp" in css
    assert "background-size:cover" in css
    assert "window.matchMedia('(prefers-reduced-motion: reduce)')" in js
    assert 'gsap@' in html
    assert 'ScrollTrigger' in js


def test_pdf_route_and_button():
    html = client.get('/').text
    assert 'id="export-pdf"' in html
    assert '/pdf-report.js' in html
    assert 'PhishGuardPDF' in client.get('/pdf-report.js').text

def test_background_assets():
    for name in ('hero-static-desktop.webp', 'hero-static-mobile.webp'):
        result = client.get('/assets/' + name)
        assert result.status_code == 200
        assert result.content[:4] == b'RIFF'

def test_api_not_replaced():
    response = client.post('/analyze', json={'message': 'Hi, our meeting is tomorrow at noon.'})
    assert response.status_code == 200
    assert response.json()['verdict'] in {'Safe', 'Suspicious', 'Scam'}
