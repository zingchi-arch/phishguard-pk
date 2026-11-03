"""Constrained official-source contact cross-check, not identity authentication.

Never browse URLs supplied in messages. Only *fixed* HTTPS pages published by
recognised organizations can be retrieved, and missing entries are inconclusive.
Official contact matching does NOT authenticate the SMS sender or guarantee safety.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlsplit
import re
import time
from threading import Lock

# Official publisher/bank references reviewed 2026-11-03. Not an exhaustive
# contacts registry. Verified source URLs should be rechecked periodically.
@dataclass(frozen=True)
class Source:
    name: str
    pattern: re.Pattern
    url: str
    official_domains: tuple[str, ...]
    published_numbers: tuple[str, ...] = ()

SOURCES = (
    Source('Jeeto Pakistan / ARY Digital', re.compile(r'\b(?:jeeto|jito|jeto)\s*pakistan\b|جیتو\s*پاکستان', re.I),
           'https://arydigital.tv/jeeto-pakistan/', ('arydigital.tv',)),
    Source('UBL', re.compile(r'\b(?:ubl|united\s*bank\s*limited)\b|یونائیٹڈ\s*بینک', re.I),
           'https://ubldigital.com/More/ContactUs', ('ubldigital.com','ubl.com.pk'),
           ('021111825888', '021111825777', '02132446949')),
    Source('HBL', re.compile(r'\b(?:hbl|habib\s*bank\s*limited)\b|حبیب\s*بینک', re.I),
           'https://www.hbl.com/', ('hbl.com',), ('021111111425',)),
    Source('JazzCash', re.compile(r'\bjazz\s*cash\b|جاز\s*کیش', re.I),
           'https://www.jazzcash.com.pk/contact-us/', ('jazzcash.com.pk',), ('03254444786',)),
    Source('Bank Alfalah', re.compile(r'\b(?:bank\s*alfalah|alfalah\s*bank)\b|بینک\s*الفلاح', re.I),
           'https://www.bankalfalah.com/contact-us/', ('bankalfalah.com',), ('021111225111',)),
    Source('Easypaisa', re.compile(r'\beasy\s*paisa\b|ایزی\s*پیسہ', re.I),
           'https://easypaisa.com.pk/', ('easypaisa.com.pk',), ('021111003737',)),
    Source('BISP', re.compile(r'\b(?:bisp|benazir|ehsaas|8171)\b|بینظیر|بے\s*نظیر', re.I),
           'https://bisp.gov.pk/', ('bisp.gov.pk',)),
)

_PHONE = re.compile(r'(?<!\d)(?:(?:\+92|0)3\d{2}[\s.\-]?\d{7,8}|(?:\+92[- ]?)?0?21[- ]?111[- ]?\d{3}[- ]?\d{3})(?!\d)')
_URL = re.compile(r'https?://[^\s<>"\']+|\bwww\.[\w.\-]+(?:/[^\s<>"\']*)?', re.I)
_CACHE: dict[str, tuple[float, str, str]] = {}
_LOCK = Lock()
_TTL_SECONDS = 1800


def _digits(raw: str) -> str:
    s = re.sub(r'\D', '', raw)
    if s.startswith('92'):
        s = '0' + s[2:]
    if s.startswith('21') and len(s) == 11:
        s = '0' + s
    return s


def _is_official_hostname(hostname: str, official_domains: tuple[str, ...]) -> bool:
    host = hostname.lower().rstrip('.')
    return any(host == d or host.endswith('.' + d) for d in official_domains)


def get_official_contact_context(message: str, claimed_org: str | None = None) -> dict | None:
    """Local inspection only. Never label an unlisted number as proven fraudulent."""
    msg = str(message or '')
    src = next((x for x in SOURCES if x.pattern.search(f'{msg} {claimed_org or ""}')), None)
    if src is None:
        return None
    phones = list(dict.fromkeys(_digits(m.group(0)) for m in _PHONE.finditer(msg)))[:5]
    urls = [m.group(0).rstrip('.,;!?)') for m in _URL.finditer(msg)][:5]
    official_urls, other_urls = 0, 0
    for item in urls:
        candidate = item if item.lower().startswith('http') else 'https://' + item
        try:
            host = urlsplit(candidate).hostname or ''
        except ValueError:
            host = ''
        if _is_official_hostname(host, src.official_domains):
            official_urls += 1
        else:
            other_urls += 1
    listed = [p for p in phones if p in src.published_numbers]
    unknown = [p for p in phones if p not in src.published_numbers]
    # Do not echo message phone numbers in the API/UI: could be personal data.
    if other_urls:
        status = 'unrecognised_claimed_link'
    elif unknown:
        status = 'number_not_in_limited_reference'
    elif listed:
        status = 'number_in_official_reference_not_sender_verified'
    elif official_urls:
        status = 'official_domain_match_sender_not_verified'
    else:
        status = 'no_contact_reference_to_compare'
    return {
        'organization': src.name, 'status': status, 'official_source_url': src.url,
        'official_domain': src.official_domains[0], 'contact_numbers_found': len(phones),
        'known_official_reference_matches': len(listed),
        'unmatched_numbers': len(unknown), 'unrecognised_url_hosts': other_urls,
        'official_domain_link_matches': official_urls,
        'verified_sender': False,
        'note': ('Official reference comparison only. Unlisted numbers may still be legitimate; '
                 'listed numbers can be spoofed. Contact the organization independently.')
    }


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.ignored: int = 0
    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.ignored += 1
    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self.ignored = max(0, self.ignored - 1)
    def handle_data(self, data):
        if not self.ignored:
            self.parts.append(data)


def _fetch_official_page(src: Source) -> tuple[str, str]:
    """Fetch only a fixed allowlisted HTTPS page, never a user-supplied URL."""
    import httpx
    uri = urlsplit(src.url)
    if uri.scheme != 'https' or not _is_official_hostname(uri.hostname or '', src.official_domains):
        return 'source_not_allowlisted', ''
    with _LOCK:
        cached = _CACHE.get(src.url)
        if cached is not None and time.monotonic() - cached[0] < _TTL_SECONDS:
            return cached[1], cached[2]
    try:
        # Redirects intentionally disabled to prevent following unknown locations.
        response = httpx.get(src.url, follow_redirects=False, timeout=2.0,
                             headers={'User-Agent': 'PhishGuard-PK-contact-check/1.0'})
        if response.status_code != 200:
            return 'official_page_unavailable', ''
        if 'text/html' not in response.headers.get('content-type', '').lower():
            return 'official_page_not_html', ''
        if len(response.content) > 256_000:
            return 'official_page_too_large', ''
        parser = _Text()
        parser.feed(response.text)
        result = ('official_page_retrieved', ' '.join(parser.parts)[:200_000])
        with _LOCK:
            _CACHE[src.url] = (time.monotonic(), *result)
        return result
    except (httpx.HTTPError, UnicodeError, ValueError):
        return 'official_page_unavailable', ''


def crosscheck_known_official_page(message: str, claimed_org: str | None = None) -> dict:
    """Best effort online corroboration. Absence of a number is NOT fraud proof."""
    c = get_official_contact_context(message, claimed_org)
    if c is None:
        return {'status': 'organization_not_in_limited_registry', 'verified_sender': False}
    result = {**c, 'online_status': 'not_checked', 'checked_at_utc': None}
    phones = list(dict.fromkeys(_digits(m.group(0)) for m in _PHONE.finditer(message)))[:5]
    if not phones:
        result['online_status'] = 'no_phone_to_crosscheck'
        return result
    src = next(x for x in SOURCES if x.name == c['organization'])
    fetch_status, body = _fetch_official_page(src)
    result['checked_at_utc'] = datetime.now(timezone.utc).isoformat()
    if fetch_status != 'official_page_retrieved':
        result['online_status'] = fetch_status
        return result
    body_digits = {_digits(x.group(0)) for x in _PHONE.finditer(body)}
    # The homepage might not list *every* verified contact. An absent number
    # must NOT be described as fake, and a listed number doesn't prove sender.
    result['online_status'] = ('number_appears_on_checked_page' if any(x in body_digits for x in phones)
                               else 'number_not_found_on_this_page_INCONCLUSIVE')
    return result
