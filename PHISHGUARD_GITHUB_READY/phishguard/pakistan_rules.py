"""Offline Pakistan-specific *risk signals*, not sender authentication.

Rules are deliberately narrow: no link is opened, no OTP is stored, an official-
looking sender never proves authenticity, and any decision is a screening opinion.
This file includes separate Urdu-script, Roman Urdu and English variants.
"""
from __future__ import annotations
import re
from dataclasses import dataclass


def rx(pattern):
    return re.compile(pattern, re.I | re.U)

BISP = rx(r'\b(?:bisp|benazir|ehsaas|8171|kafalat|kafaalat|income\s+support)\b|بے?نظیر|بینظیر|احساس|کفالت|بی\s*آئی\s*ایس\s*پی|انکم\s*سپورٹ')
JEETO = rx(r'\b(?:jeeto|jeto|jito|jeet[o]?)\s*(?:pakistan|pk)\b|جیتو\s*پاکستان|جیتوپاکستان')
PRIZE = rx(r'\b(?:prize|lottery|lucky\s*draw|winner|won|cash\s*prize|gold|tola|inaam|mubarak|congrats?|congratulations?|jeeto)\b|انعام|مبارک|لاٹری|جیت|تولہ|سونا|گولڈ|لاکھ')
STRONG_PRIZE = rx(r'\b(?:prize|winner|won|winning|lottery|lucky\s*draw|gold|tola|inaam|inaam\s*nikla|lakhs?|cash\s*prize|rs\.?\s*\d+)\b|انعام|جیت|تولہ|سونا|گولڈ|لاکھ')
WIN = rx(r'\b(?:win|winner|won|selected|congrat\w*|mubarak|inaam|prize|lucky|lottery|gold|cash)\b|انعام|مبارک|منتخب|جیت|سونا|گولڈ|انعامی')
LINK = rx(r'https?://|www\.|\[(?:URL|LINK)[_\w]*\]|\b(?:bit\.ly|tinyurl\.com|cutt\.ly|t\.co)/')
CONTACT = rx(r'\b(?:whats?app|contact|call|rabta|rabta\s*kare|sms\s*(?:to|karein)|send\s*(?:us\s*)?a\s*message|reach\s*us|is\s+number\s+par|number\s*par)\b|رابطہ|واٹس\s*ایپ|کال\s*کریں|فون\s*کریں|نمبر\s*پر|\[(?:PHONE|MOBILE)[_\w]*\]')
PAID = rx(r'\b(?:processing\s*fee|advance\s*(?:fee|payment)|pay\s*(?:rs|pkr|now)|deposit|send\s*rs|tax\s*for\s*prize|delivery\s*(?:fee|charges)|fee\s*to\s*claim|transfer\s*(?:money|rs)|jama\s*karwa|bhej\s*do|bhejein|fees|fee)\b|فیس|رقم\s*جمع|روپے\s*بھیج|ٹیکس\s*جمع|ادا\s*کریں|رقم\s*منتقل|ادائیگی\s*کریں')
CLAIM = rx(r'\b(?:approved|selected|won|win|claim|collect|cash|payment|funds?|paisa|paise|rupay|rupees|manzoor|manzur|rs\.?\s*\d|lakhs?|lacs?|mubarak|congrat\w*)\b|رقم|روپے|منظور|ملیں\s*گے|مل\s*گئے|مل\s*گئی|انعام|مبارک|ہزار|لاکھ')
BANK = rx(r'\b(?:bank|hbl|ubl|mcb|meezan|alfalah|allied|askari|faysal|habib|nbp|jazzcash|easypaisa|nayapay|sadapay|zindigi|wallet|atm)\b|بینک|اکاؤنٹ|جاز\s*کیش|ایزی\s*پیسہ')
SECRET = rx(r'\b(?:otp|one.time.password|pin|cvv|verification\s*code|password|passcode|secret\s*code|card\s*details|bank\s*details)\b|او\s*ٹی\s*پی|پاس\s*ورڈ|خفیہ\s*کوڈ|پن\s*کوڈ|بینک\s*کی\s*معلومات|کارڈ\s*کی\s*تفصیل')
ASK_SECRET = rx(r'\b(?:share|send|tell|provide|enter|submit|forward|reply|bhejo|bhejein|batayein|batao|bataen|likh|send\s*back|apna\s*otp\s*do)\b|بھیجیں|بھیجو|بتائیں|بتاؤ|درج\s*کریں|شیئر\s*کریں|فراہم\s*کریں')
NEGATION = rx(r'\b(?:do\s*not|don.t|never|avoid|beware|scam\s*alert|fake\s*message|mat\s*|na\s*\w+\s*(?:karo|karein)|kabhi\s*nahi|(?:share|bhej|bata)\s+na\s+(?:karein|karo)|kabhi\s+share\s+na|fraud\s*awareness)\b|کبھی\s*نہ|ہرگز\s*نہ|مت\s*بھیج|خبردار|جعلی\s*پیغام|نہ\s*کریں|نہ\s*بتائیں|کسی\s*کو\s*نہ|نہیں\s*بتائیں|ہرگز\s*شیئر')
CHALLAN = rx(r'\b(?:e[ -]?challan|psca|traffic\s*(?:fine|challan)|e[ -]?ticket)\b|ای\s*چالان|ٹریفک\s*چالان')
GOV_THREAT = rx(r'\b(?:fia|cyber\s*crime|police|court|nadra)\b|ایف\s*آئی\s*اے|عدالت|پولیس|نادرا')
ARREST = rx(r'\b(?:arrest|giraftar|giraftari|warrant|lawsuit|case\s*registered)\b|گرفتار|وارنٹ|مقدمہ')
PERSONAL_GREETING = rx(r'\b(?:eid|jummah|ramadan|birthday|wedding|anniversary|new\s*year)\b|عید|رمضان|جمعہ|سالگرہ|شادی')


@dataclass(frozen=True)
class Indicator:
    floor: float
    reason: str
    rule_id: str


def assess_pakistani_context(message: str, sender_id: str | None = None, claimed_org: str | None = None) -> list[Indicator]:
    """Flag scam *patterns* even when sender mimics 8171, a bank, or an authority."""
    text = str(message or '')
    context = f'{text} {claimed_org or ""}'
    flags: list[Indicator] = []
    has_link, has_contact = bool(LINK.search(text)), bool(CONTACT.search(text))
    asks_money = bool(PAID.search(text))
    # Evaluate per clause: 'Never share OTP. Now send your PIN' is NOT safe.
    clauses = re.split(r'[.!?۔;\n]+|\b(?:but|lekin|magar)\b', text, flags=re.I)
    has_secret_request = any(SECRET.search(c) and ASK_SECRET.search(c) and not NEGATION.search(c) for c in clauses)
    # Negation is a safeguard only for secret-sharing advice, NOT a blanket
    # exemption for a different prize claim appearing in the same message.
    protect_secret_advice = bool(NEGATION.search(text))

    if BISP.search(context) and CLAIM.search(text) and (has_contact or has_link or asks_money):
        flags.append(Indicator(88, 'BISP benefit claim with external contact, link, or payment instruction. Check independently through official 8171 channels.', 'PK_BISP_REDIRECT'))
    elif BISP.search(context) and sender_id and sender_id.strip() != '8171' and CLAIM.search(text):
        flags.append(Indicator(65, 'BISP benefit claim from non-8171 sender. A displayed sender ID can be spoofed and is not verified here.', 'PK_BISP_UNKNOWN_SENDER'))

    if JEETO.search(context) and WIN.search(text) and (has_contact or has_link or asks_money):
        flags.append(Indicator(90, 'Unexpected Jeeto Pakistan prize claim redirects to contact, link or payment.', 'PK_JEETO_CLAIM'))
    elif STRONG_PRIZE.search(text) and WIN.search(text) and asks_money and not PERSONAL_GREETING.search(text):
        flags.append(Indicator(90, 'Prize or winnings claim with advance fee or payment request.', 'PK_PRIZE_ADVANCE_FEE'))
    elif STRONG_PRIZE.search(text) and WIN.search(text) and (has_link or has_contact) and not PERSONAL_GREETING.search(text):
        flags.append(Indicator(72, 'Prize or reward claim includes an outside link or contact; verify independently.', 'PK_PRIZE_REDIRECT'))

    if BANK.search(context) and has_secret_request:
        flags.append(Indicator(90, 'Bank or wallet claim requests OTP, PIN, password, or card information.', 'PK_BANK_SECRET_REQUEST'))

    if CHALLAN.search(context) and has_link and not protect_secret_advice:
        flags.append(Indicator(85, 'E-challan SMS includes a link: verify by independently opening the official authority website.', 'PK_CHALLAN_LINK'))
    if CHALLAN.search(context) and sender_id and sender_id.strip() == '8070' and (has_link or asks_money):
        flags.append(Indicator(80, 'E-challan sender resembles an ID cited in 2026 spoofing warnings. Not authenticated.', 'PK_CHALLAN_8070_WARNING'))

    if GOV_THREAT.search(context) and ARREST.search(text) and (has_link or asks_money) and not protect_secret_advice:
        flags.append(Indicator(89, 'Government or police arrest threat with payment or link request.', 'PK_GOV_THREAT_PAY'))

    return sorted(flags, key=lambda x: (-x.floor, x.rule_id))


def looks_like_plain_greeting(message: str) -> bool:
    """Guard a narrow, clearly social message against synthetic-model false alarms.

    Not an authenticity check. Never applies if the content includes money, a
    prize, a contact redirect, credentials, bank claim, link or threat.
    """
    text = str(message or '').strip()
    if len(text) > 180 or not PERSONAL_GREETING.search(text):
        return False
    if not rx(r'\b(?:mubarak|happy|wishes|blessed|greetings)\b|مبارک|خوشی|دعائیں|خوشیاں').search(text):
        return False
    dangerous = (LINK, CONTACT, PAID, SECRET, BISP, JEETO, BANK, STRONG_PRIZE, GOV_THREAT, CHALLAN, ARREST)
    if any(r.search(text) for r in dangerous):
        return False
    if rx(r'\b(?:urgent|blocked|verify|payment|claim|won|free|offer|download|click|login|send|pay|reply)\b|فوری|ابھی|تصدیق|بھیجیں|دعویٰ').search(text):
        return False
    return True
