from phishguard.urls import extract_urls,url_features,heuristic_url_risk,is_unsafe_host,domain_age_days

def test_url_detection():
    assert extract_urls('Open https://example.com/path?verify=1 now')==['https://example.com/path?verify=1']
    assert extract_urls('No link here')==[]

def test_https():
    assert url_features('https://example.com')['https']==1
    assert url_features('http://example.com')['https']==0

def test_shortlink():
    assert url_features('https://bit.ly/my-link')['shortener']==1

def test_offline_domain_age():
    assert domain_age_days('example.com') is None

def test_private_ip():
    assert is_unsafe_host('127.0.0.1')
    assert is_unsafe_host('localhost')

def test_offline_heuristic():
    assert heuristic_url_risk('http://user@verify-login-bonus.invalid/claim') > heuristic_url_risk('https://www.example.com/help')
