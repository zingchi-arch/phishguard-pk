"""Offline URL feature analysis: NEVER fetches or opens the supplied URL."""
from urllib.parse import urlsplit
import re
import ipaddress
from datetime import datetime, timezone
import os

_URL_RE = re.compile(r'(?i)(?<![\w@])(?:https?://|www\.)[^\s<>\[\]"“”]+')
_SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'rb.gy', 'shorturl.at', 'ow.ly'}
_KEYWORDS = {'verify','update','login','account','free','bonus','prize','winner','claim','blocked',
             'suspend','urgent','reward','password','otp','payment','refund','bisp','e-challan',
             'confirm','security','wallet','kyc'}
_TRUSTED_EXAMPLE_DOMAINS = {'sbp.org.pk','fbr.gov.pk','ptcl.com.pk','pakistanpost.gov.pk',
                            'google.com','microsoft.com','github.com','example.com'}

def extract_urls(message: str):
    found=[]
    for m in _URL_RE.finditer(message or ''):
        raw=m.group().rstrip('.,;:!?)]}\'\"')
        if raw and raw not in found: found.append(raw)
    return found

def safe_hostname(url: str):
    try:
        parts = urlsplit(url if re.match(r'(?i)^https?://',url) else 'http://'+url)
        return (parts.hostname or '').strip('.').lower()
    except (ValueError,AttributeError):
        return ''

def is_unsafe_host(host: str) -> bool:
    if not host or len(host)>253 or any(x in host for x in (' ','\\','\n','\r')): return True
    if host in {'localhost','0.0.0.0'} or host.endswith(('.local','.internal','.test','.invalid')):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return not ip.is_global
    except ValueError:
        return False

def domain_age_days(host: str):
    """Optional WHOIS lookup, OFF by default. Never fetch phishing web pages."""
    if os.environ.get('PHISHGUARD_WHOIS','0') != '1' or is_unsafe_host(host):
        return None
    try:
        import whois  # pip install python-whois; may require network and can be slow
        entry=whois.whois(host)
        created=entry.creation_date
        if isinstance(created,list): created=min(x for x in created if isinstance(x,datetime))
        if not isinstance(created,datetime): return None
        if created.tzinfo is None: created=created.replace(tzinfo=timezone.utc)
        return max(0,(datetime.now(timezone.utc)-created).days)
    except Exception:
        return None

def url_features(url: str):
    host=safe_hostname(url)
    raw=url if re.match(r'(?i)^https?://',url) else 'http://'+url
    try: parts=urlsplit(raw)
    except ValueError: parts=urlsplit('http://invalid.invalid')
    low=url.lower()
    ip=False
    try: ipaddress.ip_address(host); ip=True
    except ValueError: pass
    tokens=re.split(r'[/._?&=+\-#]',low)
    keyword_hits=sum(1 for t in set(tokens) if t in _KEYWORDS)
    age=domain_age_days(host)
    return {
        'url_length':min(len(url),2000), 'host_length':len(host),
        'dot_count':url.count('.'), 'hyphen_count':url.count('-'),
        'at_count':url.count('@'), 'digit_count':sum(c.isdigit() for c in url),
        'special_count':sum(c in '@=?%&+#' for c in url),
        'https':int(parts.scheme.lower()=='https'),
        'shortener':int(host in _SHORTENERS), 'ip_host':int(ip),
        'keyword_hits':keyword_hits, 'many_subdomains':int(host.count('.')>=3),
        'punycode':int('xn--' in host), 'has_userinfo':int('@' in parts.netloc),
        'domain_age_days':age, 'very_new_domain':int(age is not None and age<30),
    }
FEATURE_NAMES=[
    'url_length','host_length','dot_count','hyphen_count','at_count','digit_count',
    'special_count','https','shortener','ip_host','keyword_hits','many_subdomains',
    'punycode','has_userinfo','very_new_domain']

def feature_vector(url: str):
    f=url_features(url)
    return [f[k] for k in FEATURE_NAMES]

def heuristic_url_risk(url: str):
    """Non-probabilistic indicator while supervised URL model is unvalidated."""
    f=url_features(url)
    score=5
    score+=min(30,10*f['keyword_hits'])
    score+=22*f['ip_host']+18*f['shortener']+12*f['many_subdomains']
    score+=min(20,5*f['hyphen_count'])+14*f['has_userinfo']+8*f['punycode']
    if not f['https']:score+=8
    if f['url_length']>110:score+=8
    if f['very_new_domain']:score+=15
    host=safe_hostname(url)
    if host in _TRUSTED_EXAMPLE_DOMAINS and f['keyword_hits']==0:
        score=min(score,10)  # NOT a security guarantee (URLs can contain bad paths)
    return min(100,max(0,score))

def url_reasons(url: str):
    f=url_features(url)
    reasons=[]
    if f['ip_host']:reasons.append('Link uses an IP address instead of a normal domain')
    if f['shortener']:reasons.append('Link uses a URL-shortening service')
    if f['keyword_hits']:reasons.append('URL contains verification, account or reward keywords')
    if f['many_subdomains']:reasons.append('URL has many subdomains')
    if f['has_userinfo']:reasons.append('URL contains @, which can disguise the real destination')
    if not f['https']:reasons.append('URL does not use HTTPS (HTTPS alone is not proof of safety)')
    if f['very_new_domain']:reasons.append('Domain appears to be younger than 30 days')
    if f['domain_age_days'] is None:reasons.append('Domain age not available in offline mode')
    return reasons
