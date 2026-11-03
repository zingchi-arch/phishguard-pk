"""Consistent, offline lexical URL feature engineering for URL-Phish research.

This module never resolves DNS, opens URLs or follows redirects. The model is
trained ONLY as a research candidate; production must not silently load it.
"""
from __future__ import annotations
import math
import ipaddress
import re
from collections import Counter
from urllib.parse import urlsplit
import numpy as np

FEATURES = (
    'length','host_length','path_length','query_length','fragment_length',
    'dots','hyphens','underscores','slashes','at_signs','question_marks',
    'equals','ampersands','percents','digits','digit_fraction','letters',
    'special_fraction','entropy','subdomain_depth','https','http',
    'raw_ip','punycode','has_port','host_digit_fraction',
    'query_pairs','path_depth','credential_word','reward_word',
    'government_word','host_hyphenated','host_digits','has_url_in_query',
)

CREDENTIAL = re.compile(r'(?i)(?:^|[^a-z])(login|verify|signin|sign-in|account|kyc|password|auth|otp)(?:$|[^a-z])')
REWARD = re.compile(r'(?i)(?:^|[^a-z])(gift|reward|bonus|prize|winner|claim|payment)(?:$|[^a-z])')
GOVERNMENT = re.compile(r'(?i)(?:^|[^a-z])(gov|bisp|fbr|ehsaas|challan|nadra)(?:$|[^a-z])')


def features(url: str) -> np.ndarray:
    """Fixed 34-element float vector, no network, stable for model training/inference."""
    text = str(url).strip()[:2000]
    try:
        parts=urlsplit(text if '://' in text else 'http://'+text)
        host=(parts.hostname or '').lower()
        port=parts.port
    except (ValueError, UnicodeError):
        parts=urlsplit('http://invalid.invalid')
        host=''
        port=None
    try: ipaddress.ip_address(host); is_ip=1
    except ValueError: is_ip=0
    path=parts.path or ''
    query=parts.query or ''
    hcnt=Counter(host)
    counts=Counter(text)
    n=max(1,len(text));nh=max(1,len(host))
    ent=-sum((c/n)*math.log2(c/n) for c in counts.values())
    a=[len(text),len(host),len(path),len(query),len(parts.fragment or ''),
       counts['.'],counts['-'],counts['_'],counts['/'],counts['@'],counts['?'],
       counts['='],counts['&'],counts['%'],sum(c.isdigit() for c in text),
       sum(c.isdigit() for c in text)/n,sum(c.isalpha() for c in text),
       sum(not c.isalnum() for c in text)/n,ent,
       max(0,len(host.split('.'))-2),int(parts.scheme.lower()=='https'),
       int(parts.scheme.lower()=='http'),is_ip,int('xn--' in host),int(port is not None),
       sum(c.isdigit() for c in host)/nh, min(query.count('&')+int(bool(query)),30),
       min(path.count('/'),30),int(bool(CREDENTIAL.search(path+'?'+query))),
       int(bool(REWARD.search(path+'?'+query))),int(bool(GOVERNMENT.search(host+' '+path))),
       int('-' in host),sum(c.isdigit() for c in host),int('http%3a' in query.lower() or 'https%3a' in query.lower())]
    assert len(a)==len(FEATURES), (len(a),len(FEATURES))
    return np.asarray(a,dtype=np.float32)


def features_many(urls: list[str]) -> np.ndarray:
    return np.asarray([features(x) for x in urls],dtype=np.float32)
