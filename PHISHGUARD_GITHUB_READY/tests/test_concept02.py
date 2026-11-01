from fastapi.testclient import TestClient
from phishguard.api import app

client = TestClient(app)

def test_branding_and_interaction_files():
    home = client.get('/')
    assert home.status_code == 200
    for phrase in ('Detect phishing', 'id="message"', 'id="check"', 'id="batch-panel"', 'id="result"', 'id="mobile-menu-toggle"'):
        assert phrase in home.text
    for route in ('/styles.css', '/app.js', '/motion.js', '/assets/phishguard-shield.svg', '/assets/favicon.svg', '/assets/glass-shield-desktop.webp', '/assets/glass-shield-mobile.webp', '/assets/soft-wave.svg'):
        assert client.get(route).status_code == 200, route

def test_phishing_api_unchanged():
    response = client.post('/analyze', json={'message':'Mubarak ho! Apka inaam nikla hai. Bank details bhejein.'})
    assert response.status_code == 200
    assert response.json()['verdict'] == 'Scam'
