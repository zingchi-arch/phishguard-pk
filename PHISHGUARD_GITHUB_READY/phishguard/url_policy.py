"""Step 44: conservative, offline URL-structure assessment.

Never fetches links, resolves DNS, expands shorteners, or authenticates a domain.
The indicator is not a probability of phishing. Reference domains exist ONLY
for lookalike detection, never for automatically declaring a URL safe.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit
import ipaddress
import re

# A small, dated reference set, NOT a complete official registry / allowlist.
# All reference domain comparisons require a dot boundary.
REFERENCE_DOMAINS = {
    'github': ('github.com', 'github.io'),
    'wikipedia': ('wikipedia.org', 'wikimedia.org'),
    'python': ('python.org', 'pypi.org'),
    'google': ('google.com', 'google.com.pk', 'googleapis.com', 'googleusercontent.com'),
    'microsoft': ('microsoft.com', 'microsoftonline.com'),
    'bisp': ('bisp.gov.pk',),
    'jazzcash': ('jazzcash.com.pk',),
    'meezan': ('meezanbank.com', 'meezanbank.pk'),
    'fbr': ('fbr.gov.pk',),
    'hbl': ('hbl.com',),
    'alfalah': ('bankalfalah.com',),
    'easypaisa': ('easypaisa.com.pk',),
}
# A namespace marker, not an assertion that every *.gov.pk site is authentic.
# Used solely to detect gov.pk appended to an unrelated destination hostname.
PUBLIC_SECTOR_NAMESPACE_MARKERS = ('gov.pk',)
SHORTENERS = frozenset({'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'rb.gy', 'ow.ly', 'shorturl.at'})
AUTH_ACTION = re.compile(r'(?i)(?:^|[/?#&=_-])(?:login|signin|sign-in|verify|verification|reset-password|password|otp|kyc|claim-prize|claim)(?:$|[/?#&=_-])')
SCAM_BAIT = re.compile(r'(?i)(?:^|[/?#&=_-])(?:prize|winner|free-money|claim-reward|cash-reward|bisp-payment|8171-payment)(?:$|[/?#&=_-])')


def _is_domain_or_subdomain(host: str, domain: str) -> bool:
    return host == domain or host.endswith('.' + domain)


def _brand_host_signal(host: str):
    """(impersonation severity, reason) based on embedded brand/domain markers.

    No ownership claim: official domains may be compromised and lookalike sites
    may be benign. Signals are intentionally conservative.
    """
    for marker in PUBLIC_SECTOR_NAMESPACE_MARKERS:
        if _is_domain_or_subdomain(host, marker):
            continue
        if host.startswith(marker + '.') or ('.' + marker + '.') in host or host.startswith(marker + '-'):
            return 88, 'Hostname includes a government-style .gov.pk marker but points to another domain.'
        dashed = marker.replace('.', '-')
        if (host.startswith(dashed + '.') or host.startswith(dashed + '-')) and re.search(
            r'(?i)(?:verify|payment|8171|challan|account|login|claim)', host
        ):
            return 82, 'Hostname imitates a government domain spelling with payment or verification language.'
    for brand, official_domains in REFERENCE_DOMAINS.items():
        if any(_is_domain_or_subdomain(host, domain) for domain in official_domains):
            continue
        # An entire reference domain prepended to a different hostname is a
        # strong deceptive-host signal: github.com.evil.org != github.com.
        if any(host.startswith(domain + '.') or ('.' + domain + '.') in host
               or host.startswith(domain + '-') for domain in official_domains):
            return 88, f'Domain resembles {brand} but the actual hostname is different; check the full hostname.'
        # Entire official domain with dots swapped for hyphens, for example
        # bisp-gov-pk.verify.example. Strong spoof cue only when combined with
        # account/payment context; do not classify all mentions as phishing.
        for domain in official_domains:
            dashed = domain.replace('.', '-')
            if (host.startswith(dashed + '.') or host.startswith(dashed + '-')) and re.search(
                r'(?i)(?:login|verify|payment|8171|claim|otp|kyc|prize|reward|account)', host
            ):
                return 82, f'Hostname uses a hyphenated spelling of a {brand} reference with a sensitive action.'
        # Bounded brand tokens with login / verification cues can be suspicious;
        # ordinary brand-related fan/project domains are not automatically scams.
        if re.search(r'(?i)(?:^|[.-])' + re.escape(brand) + r'(?:[.-]|$)', host):
            if re.search(r'(?i)(?:login|verify|secure|claim|payment|support|kyc|account|prize|8171|reward|bonus)', host):
                return 68, f'Hostname combines a {brand} reference with account or verification language.'
            return 33, f'Hostname mentions {brand}, but ownership is not verified.'
    return 0, ''


@dataclass(frozen=True)
class URLAssessment:
    indicator: int
    reasons: tuple[str, ...]
    hostname: str
    status: str
    high_confidence_structure: bool


def assess_url(url: str) -> URLAssessment:
    """Returns interpretable offline indicator 0-100; NOT a fraud probability."""
    if not isinstance(url, str) or not url.strip() or len(url) > 10000:
        return URLAssessment(70, ('URL could not be parsed safely.',), '', 'invalid', True)
    raw = url.strip()
    candidate = raw if re.match(r'(?i)^https?://', raw) else 'http://' + raw
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or '').strip('.').lower()
        port = parts.port  # validates invalid port values
        if not host or any(c.isspace() for c in host) or '\\' in raw or '%' in host:
            raise ValueError('Invalid hostname')
        # Convert unicode domains for reliable ASCII label processing.
        ascii_host = host.encode('idna').decode('ascii')
        if len(ascii_host) > 253 or any(len(label) > 63 or not label for label in ascii_host.split('.')):
            raise ValueError('Invalid DNS labels')
    except (ValueError, UnicodeError):
        return URLAssessment(70, ('Malformed or ambiguous URL structure. Avoid opening it.',), '', 'invalid', True)

    score = 8
    reasons = []
    high = False
    brand_score, brand_reason = _brand_host_signal(ascii_host)
    if brand_score:
        score = max(score, brand_score)
        reasons.append(brand_reason)
        high |= brand_score >= 75

    if parts.username is not None or parts.password is not None or '@' in parts.netloc:
        score = max(score, 82)
        reasons.append('URL contains @ / userinfo: the apparent domain before @ may not be the destination.')
        high = True

    ip = None
    try:
        ip = ipaddress.ip_address(ascii_host.strip('[]'))
    except ValueError:
        pass
    if ip:
        if ip.is_global:
            score = max(score, 45)
            reasons.append('Destination uses a numeric IP rather than a domain name.')
        else:
            score = max(score, 28)
            reasons.append('Destination is an internal, private or reserved IP address; cannot verify it as a public site.')

    if ascii_host in SHORTENERS:
        score = max(score, 48)
        reasons.append('Shortened link hides its final destination; it has not been expanded.')

    if 'xn--' in ascii_host or any(ord(c) > 127 for c in host):
        score = max(score, 48)
        reasons.append('Internationalized / punycode hostname; visually similar letters may be confusing.')

    if len(ascii_host.split('.')) >= 5:
        score = max(score, 31)
        reasons.append('Hostname has several subdomain levels; inspect its real ending carefully.')

    # Only a compounded, contextual signal. HTTP alone is not phishing;
    # HTTPS alone is not proof of legitimacy.
    pathquery = (parts.path or '') + '?' + (parts.query or '')
    action = bool(AUTH_ACTION.search(pathquery))
    bait = bool(SCAM_BAIT.search(pathquery))
    if action and parts.scheme.lower() == 'http':
        score = max(score, 52)
        reasons.append('Account/verification action on unencrypted HTTP link.')
    elif action and score >= 33:
        score = max(score, 53)
        reasons.append('Account/verification action adds risk to an already unusual hostname.')
    if bait and score >= 33:
        score = max(score, 58)
        reasons.append('Prize/reward keywords appear with other URL warning signs.')
    if port not in (None, 80, 443):
        score = max(score, 34)
        reasons.append('URL uses a nonstandard network port.')
    if len(raw) > 250:
        score = max(score, 33)
        reasons.append('Unusually long link, inspect the complete destination.')

    if not reasons:
        reasons.append('No strong offline structural warning found; this does NOT verify the website is safe.')
    status = 'high_structural_risk' if score >= 75 else ('caution' if score >= 45 else 'low_indicators_not_verified')
    return URLAssessment(min(100, int(score)), tuple(reasons), ascii_host, status, high)
