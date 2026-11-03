"""Offline Pakistan-specific *risk signals*, not sender authentication.

Rules are deliberately narrow: no link is opened, no OTP is stored, an official-
looking sender never proves authenticity, and any decision is a screening opinion.
This file includes separate Urdu-script, Roman Urdu and English variants.
"""
from __future__ import annotations
import re
from .message_intent import interpret_secret_intent
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
SECURITY_WARNING = rx(r'\b(?:do\s*not\s*share|don.t\s*share|never\s*share|beware\s+of\s+(?:scam|fraud)|scam\s+alert|fake\s+(?:message|link)|fraud\s+awareness|kabhi\s+(?:share|bata)\s+na|kisi\s+ko\s+na\s+batayein)\b|جعلی\s*پیغام|کسی\s*کو\s*نہ\s*بتائیں|ہرگز\s*شیئر\s*نہ|او\s*ٹی\s*پی\s*کسی\s*کو\s*نہ')
JOB_VISA = rx(r'\b(?:job|visa|work\s*permit|appointment\s*letter|naukri|nokri|sarkari\s*job|vacancy|recruitment)\b|نوکری|ملازمت|ویزا|جاب')
ADVANCE_FEE = rx(r'\b(?:processing\s*fee|registration\s*fee|advance\s*fee|security\s*deposit)\b|رجسٹریشن\s*فیس|پروسیسنگ\s*فیس|پیشگی\s*رقم')
PAY_TO_WALLET = rx(r'\b(?:jazzcash|easypaisa|sadapay|nayapay|wallet|private\s*account)\b|جاز\s*کیش|ایزی\s*پیسہ|ذاتی\s*اکاؤنٹ')
BANK_ACCOUNT_THREAT = rx(r'\b(?:account|acount|acct|atm\s+card)\b|اکاؤنٹ|اَکاؤنٹ|بینک\s*کھاتہ')
BLOCK_STATUS = rx(r'\b(?:block(?:ed)?|freeze|frozen|suspend(?:ed)?|band\s*ho|bnd\s*ho)\b|بند\s*ہو|معطل')
PRIVATE_MOBILE = rx(r'(?<!\d)(?:\+92|0)3\d{2}[- .]?\d{7,8}(?!\d)')
# Unexpected prize-award wording common in Roman Urdu SMS. Keep prize vs. plain
# bank account approval separate: these are signals, not proof of fraud.
AWARD = rx(r'\b(?:manzoor|manzur|manzoori|approv(?:e|ed|al)|award(?:ed)?|won|winner|winning|jeet(?:a|e|i|ay)?|nikl(?:a|i|ay|e)|nkal(?:a|i|ay)|mil(?:a|i|ay|e)|selected|inaam|prize|mubarak)\b|منظور|انعام|جیت|نکل|مل\s*گئ|مبارک|منتخب')
PRIZE_ITEM = rx(r'\b(?:honda|bike|motor\s*cycle|motorcycle|car|gaari|gari|gold|sona|cash|paisa|paise|rupees?|rupay|lakhs?|tola|gift|reward|inaam|prize|lottery|draw|iphone|mobile\s*phone)\b|موٹر\s*سائیکل|بائیک|گاڑی|کار|سونا|گولڈ|انعام|رقم|روپے|لاکھ|تحفہ')
CONTACT_REDIRECT = rx(r'\b(?:what(?:s|z)?app|watsapp|whatsap|wa\s*me|rabta|contact|call|reach|msg|message|sms|reply|jawab|sampark|is\s*number\s*(?:par|pe))\b|واٹس\s*ایپ|واٹس\s*اپ|رابطہ|فون\s*کریں|نمبر\s*پر|کال\s*کریں')
PRIZE_WARNING = rx(r'\b(?:beware|fraud\s*alert|scam\s*alert|scams?\s+(?:are\s+)?fake|fake\s*(?:prize|message|number)|fraud\s*hai|scam\s*hai|jhoot(?:a|i)?\s*hai|reply\s*mat\s*karo|rabta\s*na\s*karo|(?:do\s*not|don.t|never)\s*(?:call|contact|reply)|(?:contact|rabta|reply)\s+(?:mat|na|nahi))\b|جعلی\s*انعام|فراڈ\s*پیغام|دھوکہ|انعامی\s*فراڈ')
IMMEDIATE_RESPONSE = rx(r'\b(?:abhi|foran|immediately|urgent|call\s*karein|sms\s*karin|pin\s*code\s*dain|details\s*send|warna)\b|فوراً|ابھی|ورنہ|فوری')



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
    has_secret_request = interpret_secret_intent(text).unsafe_secret_request
    # Negation is a safeguard only for secret-sharing advice, NOT a blanket
    # exemption for a different prize claim appearing in the same message.
    # Generic words such as 'avoid' (e.g. 'pay to avoid arrest') are
    # NOT a security warning.  Use an explicit advice phrase instead.
    protect_secret_advice = bool(SECURITY_WARNING.search(text))

    if BISP.search(context) and CLAIM.search(text) and (has_contact or has_link or asks_money):
        flags.append(Indicator(88, 'BISP benefit claim with external contact, link, or payment instruction. Check independently through official 8171 channels.', 'PK_BISP_REDIRECT'))
    elif BISP.search(context) and sender_id and sender_id.strip() != '8171' and CLAIM.search(text):
        flags.append(Indicator(65, 'BISP benefit claim from non-8171 sender. A displayed sender ID can be spoofed and is not verified here.', 'PK_BISP_UNKNOWN_SENDER'))

    # First distinguish an actual prize notification redirect from a news or
    # safety warning ABOUT scams. A named show is not evidence of authenticity.
    award_claim = bool(AWARD.search(text))
    prize_item = bool(PRIZE_ITEM.search(text))
    personal_contact = bool(PRIVATE_MOBILE.search(text))
    redirect = bool(CONTACT_REDIRECT.search(text)) and (has_contact or personal_contact)
    warned_about_prize = bool(PRIZE_WARNING.search(text))
    if JEETO.search(context) and award_claim and (redirect or has_link or asks_money or personal_contact) and not warned_about_prize:
        flags.append(Indicator(92, 'Jeeto Pakistan/Honda prize approval redirects to a personal contact, WhatsApp or link. The claim and contact are NOT authenticated; verify through ARY Digital official channels.', 'PK_JEETO_CLAIM'))
    elif award_claim and prize_item and (redirect or has_link) and personal_contact and not warned_about_prize:
        flags.append(Indicator(88, 'Unexpected prize, bike, cash or gold award asks you to contact a private mobile/WhatsApp number. High-risk prize-claim pattern; source is unverified.', 'PK_PRIZE_PRIVATE_WHATSAPP'))
    elif STRONG_PRIZE.search(text) and WIN.search(text) and asks_money and not PERSONAL_GREETING.search(text) and not warned_about_prize:
        flags.append(Indicator(90, 'Prize or winnings claim with advance fee or payment request.', 'PK_PRIZE_ADVANCE_FEE'))
    elif STRONG_PRIZE.search(text) and WIN.search(text) and (has_link or has_contact) and not PERSONAL_GREETING.search(text) and not warned_about_prize:
        flags.append(Indicator(72, 'Prize or reward claim includes an outside link or contact; verify independently.', 'PK_PRIZE_REDIRECT'))

    if BANK.search(context) and has_secret_request:
        flags.append(Indicator(90, 'Bank or wallet claim requests OTP, PIN, password, or card information.', 'PK_BANK_SECRET_REQUEST'))

    # Fake bank-block messages redirect victims to a PERSONAL 03xx mobile.
    # A generic bank transaction alert saying 'call the helpline' must NOT match.
    if (BANK.search(context) and BANK_ACCOUNT_THREAT.search(text) and
            BLOCK_STATUS.search(text) and PRIVATE_MOBILE.search(text) and
            IMMEDIATE_RESPONSE.search(text) and not protect_secret_advice):
        flags.append(Indicator(82, 'Claimed blocked bank/wallet account demands an urgent reply to a private mobile number. Verify through the bank app or independently found helpline.', 'PK_BANK_BLOCK_PRIVATE_MOBILE'))

    if CHALLAN.search(context) and has_link and not protect_secret_advice:
        flags.append(Indicator(85, 'E-challan SMS includes a link: verify by independently opening the official authority website.', 'PK_CHALLAN_LINK'))
    if CHALLAN.search(context) and sender_id and sender_id.strip() == '8070' and (has_link or asks_money):
        flags.append(Indicator(80, 'E-challan sender resembles an ID cited in 2026 spoofing warnings. Not authenticated.', 'PK_CHALLAN_8070_WARNING'))

    if GOV_THREAT.search(context) and ARREST.search(text) and (has_link or asks_money) and not protect_secret_advice:
        flags.append(Indicator(89, 'Government or police arrest threat with payment or link request.', 'PK_GOV_THREAT_PAY'))

    # A paid official application may exist; flag high risk only where a
    # job/visa promise redirects advance fees to a consumer wallet.
    if JOB_VISA.search(context) and ADVANCE_FEE.search(text) and PAY_TO_WALLET.search(text) and asks_money and not protect_secret_advice:
        flags.append(Indicator(83, 'Job or visa approval claim requests a processing fee through a personal/payment-wallet channel. Verify using the official portal.', 'PK_JOB_VISA_WALLET_FEE'))

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
