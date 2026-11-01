"""Reusable multilingual text normalization. Keeps phishing signals intact."""
import re
import unicodedata

ROMAN_NORMALIZATION = {
    'kia': 'kya', 'kiya':'kya', 'kyaa':'kya',
    'apka':'aapka', 'apki':'aapki', 'apko':'aapko',
    'aapka':'aapka', 'aapki':'aapki', 'aapko':'aapko',
    'krain':'karein', 'kren':'karein', 'karey':'karein',
    'foran':'foran', 'foran':'foran', 'foran':'foran',
    'paise':'paisy', 'pese':'paisy',
    'account':'account', 'acount':'account',
    'taseeq':'tasdeeq', 'tasdeek':'tasdeeq', 'tasdiq':'tasdeeq',
    'mubarak':'mubarak', 'mubrak':'mubarak',
    'link':'link', 'lnk':'link',
}
_URL = re.compile(r'(?i)\b(?:https?://|www\.)[^\s<>]+')
_EMAIL = re.compile(r'\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b', re.I)
_PHONE = re.compile(r'(?<!\w)(?:\+?92[\s-]?|0)3\d{2}[\s-]?\d{3}[\s-]?\d{4}(?!\w)')
_WORD = re.compile(r'[\w\u0600-\u06ff]+', re.UNICODE)
_NEGATIONS = {'not','no','never','nahi','nahin','mat','نہیں','نہ','مت'}
_STOPWORDS = {'the', 'a','an','and','is','are','of','on','in','for','to','at','it','you',
              'ka','ki','ke','ko','hai','hain','aur','ye','wo','ہے','ہیں','اور','کے','کی','کا'}

def normalize_message(message: str, remove_stopwords: bool = False) -> str:
    """Normalize Urdu letter variants and Roman Urdu spelling, preserve URL/OTP cues."""
    text = unicodedata.normalize('NFKC', str(message or '')).lower()
    for a, b in [('ك','ک'),('ي','ی'),('ى','ی'),('ة','ہ'),('ۀ','ہ'),('\u200c',''),('\u200d',''),('\ufeff','')]:
        text = text.replace(a,b)
    text = _URL.sub(' URLTOKEN ', text)
    text = _EMAIL.sub(' EMAILTOKEN ', text)
    text = _PHONE.sub(' PHONETOKEN ', text)
    # Retain punctuation cues via marker features.
    text = text.replace('!', ' EXCLAIM ').replace('؟',' QUESTION ').replace('?', ' QUESTION ')
    text = re.sub(r'\d+', ' NUMTOKEN ', text)
    words = _WORD.findall(text)
    out = []
    for w in words:
        w = ROMAN_NORMALIZATION.get(w,w)
        if remove_stopwords and w in _STOPWORDS and w not in _NEGATIONS:
            continue
        out.append(w)
    return ' '.join(out)

_URDU = re.compile(r'[\u0600-\u06ff]')
_ROMAN_WORDS = {'aap','apka','aapka','apki','aapki','apko','aapko','kya','kia','kiya','hai',
                'hain','nahi','nahin','kar','karo','karein','krain','paisy','paise','mubarak',
                'ap','main','mera','meri','ki','ka','ke','ko','se','par','wala','wali',
                'mat','foran','tasdeeq','taseeq','bhejein','bhejo','apnay','apne','band','ho',
                'raha','rha','hain','hoga','krna','karnay','milay','milega','nikla'}

def detect_language(message: str) -> str:
    """Heuristic: may confuse mixed English and Roman Urdu. Never claim verified."""
    text = str(message or '')
    if len(_URDU.findall(text)) >= 2:
        return 'Urdu'
    words = [w.lower() for w in re.findall(r'[A-Za-z]+', text)]
    hits = sum(w in _ROMAN_WORDS for w in words)
    return 'Roman Urdu' if hits >= 2 or (len(words) <= 4 and hits>=1) else 'English'
