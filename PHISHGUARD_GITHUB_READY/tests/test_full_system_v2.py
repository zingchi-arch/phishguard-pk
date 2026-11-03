"""End-to-end local checks for the FastAPI application and batch screening."""
from fastapi.testclient import TestClient
from phishguard.api import app

client=TestClient(app)

def test_home_website_and_files():
    r=client.get('/')
    assert r.status_code==200
    for phrase in ('Detect phishing', 'English', 'Roman Urdu','اردو','Batch CSV'):
        assert phrase in r.text
    assert client.get('/styles.css').status_code==200
    js=client.get('/app.js')
    assert js.status_code==200 and 'analyze/batch' in js.text

def test_health_and_model_status():
    health=client.get('/health').json()
    assert health['status']=='ok'
    status=client.get('/model-status').json()
    assert status['text_model_available'] is True
    assert 'Urdu' in status['language_support']

def test_single_message_and_website_result():
    r=client.post('/analyze',json={'message':'Your bank account will be blocked. Verify your OTP now.'})
    assert r.status_code==200
    data=r.json()
    assert data['verdict'] in ['Scam','Suspicious']
    assert data['language_detected']=='English'
    assert 'explanation' in data

def test_roman_and_urdu():
    for m,expected in [
        ('Mubarak ho apka inaam nikla hai, apni bank details bhejein','Roman Urdu'),
        ('مبارک ہو آپ نے انعام جیت لیا ہے، اپنی بینک معلومات فراہم کریں','Urdu')
    ]:
        r=client.post('/analyze',json={'message':m})
        assert r.status_code==200
        assert r.json()['language_detected']==expected

def test_batch_order_and_errors():
    messages=['Your appointment is confirmed for tomorrow.',
              'Apka account block ho raha hai, OTP bhejein.',
              'مبارک ہو، اپنا پاس ورڈ بھیجیں']
    r=client.post('/analyze/batch',json={'messages':messages})
    assert r.status_code==200
    data=r.json()
    assert data['count']==3 and len(data['results'])==3
    assert [x['row'] for x in data['results']]==[1,2,3]
    assert [x['message'] for x in data['results']]==messages
    assert all('verdict' in x['result'] for x in data['results'])

def test_input_limits_and_blank_rejected():
    assert client.post('/analyze',json={'message':' '}).status_code==422
    assert client.post('/analyze',json={'message':'a'*10001}).status_code==422
    assert client.post('/analyze/batch',json={'messages':['hello']*101}).status_code==422
    assert client.post('/analyze/batch',json={'messages':['']}).status_code==422

def test_user_payload_not_rendered_in_html():
    suspicious='<script>alert(1)</script>'
    r=client.post('/analyze',json={'message':suspicious})
    assert r.status_code==200
    assert suspicious not in client.get('/').text
    # Browser frontend uses textContent (not injecting returned user text as HTML).
    assert 'textContent' in client.get('/app.js').text

def test_reserved_url_not_fetched_and_scored():
    r=client.post('/analyze',json={'message':'Review: http://example.invalid/login'})
    assert r.status_code==200
    assert r.json()['urls']
    assert r.json()['url_model_status']=='offline_structural_rules_unvalidated'
