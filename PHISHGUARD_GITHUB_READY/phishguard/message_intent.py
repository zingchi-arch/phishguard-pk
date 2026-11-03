"""Conservative, offline context recognition for credential warnings versus requests.

This is NOT a transformer or proof of sender authenticity.  Unlike keyword-only
checks, it looks at polarity, clause boundaries, and mixed warning + solicitation.
Never uploads user text or accesses remote services.
"""
from __future__ import annotations
from dataclasses import dataclass
import re

_SECRET = re.compile(r'\b(?:otp|one[ -]?time[ -]?password|pin|cvv|pass(?:word|code)|verification\s+code|card\s+(?:detail|number)|bank\s+details|secret\s+code)\b|او\s*ٹی\s*پی|ون\s*ٹائم|پاس\s*ورڈ|پن\s*کوڈ|بینک\s*کی\s*معلومات|کارڈ\s*کی\s*تفصیل|خفیہ\s*کوڈ|\bپن\b', re.I)

# Inflected English, Roman-Urdu and Urdu commands and spelling variants.
_PROTECT = [
    r'\b(?:do\s*not|don[\'’]?t|never|avoid|must\s+not|should\s+not)\s+(?:\w+\s+){0,5}?(?:share|send|give|tell|reveal|disclose|provide|forward)\b',
    r'\b(?:share|send|bhej\w*|bata\w*|de\s*do|forward|provide|tell)\s+(?:na|mat|nahi|nai|nahin|nh|not|never)\b',
    r'\b(?:mat|na|kabhi\s+na|kabhi\s+nahi|hargiz\s+na)\s+(?:\w+\s+){0,4}?(?:share|bhej\w*|bata\w*|send|forward|provide|dena|do)\b',
    r'\b(?:share|bhej\w*|bata\w*|send|forward)\s+(?:\w+\s+){0,2}?(?:nahi|nai|nahin|nh)\s+(?:karna|karain|karein|karo|krna|krain|kren)\b',
    r'(?:شیئر|بتا\w*|بھیج\w*|دیں)\s*(?:نہ|مت|نہیں)\s*(?:کریں|کرنا|کرے|دیں|دو)?',
    r'(?:نہ|مت|نہیں)\s*(?:شیئر|بتا\w*|بھیج\w*|دیں|دو|کریں)',
    r'(?:کسی\s+کو\s+نہ\s*(?:بتا\w*|بھیج\w*|دیں))',
]
_PROTECT_RX = [re.compile(x,re.I|re.U) for x in _PROTECT]
_ACTION = re.compile(r'\b(?:send|share|tell|provide|enter|submit|forward|reply|give|reveal|disclose|bhej\w*|bata\w*|batay\w*|dein|dena|daalo|dalo|likh\w*|verify\s+(?:with|using))\b|(?:بھیج\w*|بتا\w*|شیئر|درج\s*کریں|فراہم\s*کریں|دیں)',re.I|re.U)
# Pronouns only carry a credential forward across a short adversarial clause.
_PRONOUN = re.compile(r'\b(?:it|this|that|the\s+code|ye|isko|issay|woh|use|usko)\b|اسے|اس\s*کو|یہ\s*کوڈ', re.I|re.U)
_REDIRECT = re.compile(r'\b(?:click|open|visit|follow\s+this\s+link|login\s+(?:here|at)|pay\s+(?:now|rs)|deposit|jama\s+karwa|fee\s+bhejo)\b|کلک\s*کریں|رقم\s*جمع\s*کرائیں|فیس\s*جمع\s*کریں',re.I|re.U)
# A fake exception to a secrecy warning is itself a request.
_EXCEPTION = re.compile(r'\b(?:except|unless|only\s+(?:to|with)|sirf\s+(?:hamare|mujhe|mujhse)|magar\s+humein|lekin\s+humein)\b|سوائے|صرف\s+ہمیں',re.I|re.U)
_SPLIT = re.compile(r'[.!?۔؛;\n,]+|\b(?:but|however|lekin|magar)\b|(?:لیکن|مگر)',re.I|re.U)
_PRIZE_BAIT = re.compile(r'\b(?:prize|lottery|winner|winnings|inaam|inaami|jeet\s*(?:gaye|liya|li|gya)|claim\s+(?:prize|reward)|won\s+(?:a|the|rs))\b|انعام|لاٹری|جیت\s*(?:گئے|لیا|لی)',re.I|re.U)
_SOCIAL_ENGINEERING = re.compile(r'\b(?:pay\s+(?:now|rs)|transfer\s+(?:money|rs)|processing\s+fee|advance\s+fee|arrest\s+warrant|account\s+(?:will\s+be\s+)?blocked|fake\s+bank\s+agent)\b|فیس\s*جمع|گرفتاری\s*کا\s*وارنٹ', re.I|re.U)

@dataclass(frozen=True)
class SecretIntent:
    protective_advice: bool
    unsafe_secret_request: bool
    protective_only: bool
    reason: str


def interpret_secret_intent(message: str) -> SecretIntent:
    """Distinguish 'do not share OTP' from 'send us OTP' conservatively.

    A later 'send it to us' refers to an earlier OTP/PIN only within a short
    distance. A malicious link / payment instruction invalidates protective_only
    at the inference layer, not here.
    """
    s = str(message or '').strip()
    if not _SECRET.search(s):
        return SecretIntent(False,False,False,'')
    clauses = [c.strip() for c in _SPLIT.split(s) if c.strip()]
    protected, requested = False,False
    recent_credential = 0
    for c in clauses:
        has_secret = bool(_SECRET.search(c))
        is_protection = any(r.search(c) for r in _PROTECT_RX)
        is_exception = bool(_EXCEPTION.search(c))
        # Remove only the *protected action*, not the entire clause. An
        # attacker can put 'send PIN' and 'never share it' in one sentence.
        unprotected_actions = c
        if is_protection:
            protected=True
            for protective_rx in _PROTECT_RX:
                unprotected_actions = protective_rx.sub(' ', unprotected_actions)
            if is_exception:
                requested=True
        has_unprotected_action = bool(_ACTION.search(unprotected_actions))
        if has_secret and has_unprotected_action:
            requested=True
        # 'Never share your OTP. But send it to this number' has no second OTP
        # token, but is still a credential-sharing instruction.
        elif recent_credential and not has_secret and has_unprotected_action and _PRONOUN.search(c):
            requested=True
        recent_credential = 2 if has_secret else max(0,recent_credential-1)
    return SecretIntent(
        protective_advice=protected,
        unsafe_secret_request=requested,
        protective_only=protected and not requested and not _PRIZE_BAIT.search(s) and not _SOCIAL_ENGINEERING.search(s),
        reason='This message advises you NOT to share a PIN, OTP or password. Mentioning a credential is not itself a request for it.' if protected and not requested else ''
    )
