"""Rebuild the local, free, open-source message-intent model.

Uses scikit-learn (BSD-3-Clause) char TF-IDF plus logistic regression.
All generated training examples are *development* examples, not genuine SMS,
and no derived metric is a real-world fraud accuracy estimate.
"""
from __future__ import annotations
import itertools
import random
from pathlib import Path
import joblib
from sklearn.pipeline import make_pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / 'models' / 'intent_ai_step59.joblib'
SEED = 5903


def get_development_examples():
    examples = []
    def add(label, texts):
        for s in texts:
            examples.append((s, label))

    roman_secrets = ['pin', 'otp', 'password', 'verification code', 'bank details', 'cvv']
    roman_prefix = ['HBL alert:', 'JazzCash update:', 'Easypaisa message:', 'Dear customer,', 'Apka account activate ho gaya,', 'Mubarak ho apka account ban gya,', 'For your security,', 'Bank safety tip:', '']
    roman_protect = [
        'apna {secret} kisi k sath share na krna',
        'apna {secret} kisi kay sath share na karna',
        'apni {secret} kisi ko bilkul bhi na dena',
        'apna {secret} kisi ko na batana',
        '{secret} kabhi kisi ko mat bhejna',
        'apna {secret} kisi ko mat batao',
        '{secret} share nh krna kisi se',
        '{secret} kisi ko share nai karna',
        'kisi ko bhi {secret} na bhejein',
        'apne {secret} ko private rakhein, kisi ko mat dain',
        'apna {secret} kabhi bhi kisi k sath share nahi krein',
        '{secret} sirf apne pas rkho kisi k sath share na krna',
        'aap se {secret} nahi manga jata kisi ko mat batayen',
    ]
    roman_request = [
        'apna {secret} abhi humein share karo',
        'apna {secret} verification k liye bhejo',
        'hamare agent ko {secret} bata do',
        'account unlock krwane k liye {secret} send krain',
        'kindly apni {secret} send kar dein',
        '{secret} is number per send kren',
        '{secret} ke baghair account block ho jayega, fori bhejo',
        '{secret} hamein provide karein',
        'apni {secret} reply mein likh den',
        'aap ka {secret} chahiye, foran share karein',
    ]
    english_protect = [
        'Never share your {secret} with anyone.',
        'Do not send your {secret} to any agent.',
        'Keep your {secret} private and confidential.',
        'We will never ask for your {secret}.',
        'Avoid revealing your {secret} to strangers.',
        'Do not provide your {secret} to anyone.',
        'Your {secret} is secret. Never give it away.',
        'Please do not disclose your {secret} on calls or in chats.',
    ]
    english_request = [
        'Reply with your {secret} to verify the account.',
        'Please send your {secret} to our agent.',
        'Provide your {secret} so that we can unlock the account.',
        'Enter your {secret} in the message now.',
        'Give us your {secret} immediately to continue.',
        'Tell our team your {secret} for activation.',
        'We need your {secret}. Send it here.',
    ]
    urdu_protect = [
        'اپنا {secret} کسی کو نہ بتائیں۔',
        'براہ کرم اپنا {secret} کسی کے ساتھ شیئر نہ کریں۔',
        'کبھی بھی اپنا {secret} کسی کو مت بھیجیں۔',
        'حفاظت کے لیے اپنا {secret} خفیہ رکھیں۔',
        'اپنا {secret} کسی کو نہ دیں۔',
        'آپ سے کبھی {secret} نہیں مانگا جاتا۔',
    ]
    urdu_request = [
        'براہ کرم اپنا {secret} ہمیں بھیجیں۔',
        'تصدیق کے لیے اپنا {secret} فوراً بتائیں۔',
        'اپنا {secret} اس نمبر پر شیئر کریں۔',
        'اکاؤنٹ کھولنے کے لیے اپنا {secret} دیں۔',
        'اپنا {secret} یہاں درج کریں۔',
    ]
    urdu_secrets = ['او ٹی پی', 'پن کوڈ', 'پاس ورڈ', 'خفیہ کوڈ']
    samples_protect = []
    samples_request = []
    for prefix, pattern, secret in itertools.product(roman_prefix, roman_protect, roman_secrets):
        samples_protect.append((prefix + ' ' + pattern.format(secret=secret)).strip())
    for prefix, pattern, secret in itertools.product(roman_prefix, roman_request, roman_secrets):
        samples_request.append((prefix + ' ' + pattern.format(secret=secret)).strip())
    for pattern, secret in itertools.product(english_protect, ['OTP', 'PIN', 'password', 'verification code']):
        samples_protect.append('Security notice: ' + pattern.format(secret=secret))
    for pattern, secret in itertools.product(english_request, ['OTP', 'PIN', 'password', 'verification code']):
        samples_request.append('Security notice: ' + pattern.format(secret=secret))
    for pattern, secret in itertools.product(urdu_protect, urdu_secrets):
        samples_protect.append(pattern.format(secret=secret))
    for pattern, secret in itertools.product(urdu_request, urdu_secrets):
        samples_request.append(pattern.format(secret=secret))
    add('protect', samples_protect)
    add('request', samples_request)
    # Mixed coercive examples must never be treated as protective.
    mixed = [
        'Never share your OTP with anyone, but send it to us now.',
        'Do not share your PIN with strangers, only provide it to our agent.',
        'Keep OTP private except for this verification. Reply with the code.',
        'Never reveal the password to anyone, but enter it at this link: https://example.test/login',
        'Apna otp kisi ko mat batana, magar hamein foran send kr do.',
        'OTP share na krna lekin hamare staff ko zaroor batao.',
        'kisi se pin share nahi krna, sirf hamare agent ko send karo',
        'apna pin kisi ko na dena magar verification k liye humein do',
        'اپنا او ٹی پی کسی کو نہ بتائیں، لیکن ہمیں فوراً بھیجیں۔',
        'کسی کو پن نہ بتائیں مگر ہمارے ایجنٹ کو بتائیں۔',
        'OTP kisi ke sath share na kro. Lekin ye code humein send krdo.',
        'We will never ask for your PIN, except that you must send it to us here.',
    ]
    # Use separate mixed phrases with multiple credential names and real prefixes.
    for m in mixed:
        add('mixed', [m])
        if 'OTP' in m: add('mixed',[m.replace('OTP','PIN'),m.replace('OTP','password')])
        if 'otp' in m: add('mixed',[m.replace('otp','pin'),m.replace('otp','password')])
    # Non-credential messages and mere mentions are neither advice nor an ask.
    other = [
        'Your account is activated. Welcome to JazzCash.',
        'Rs 10,000 has been credited to your wallet.',
        'Your bank statement is ready. Open the official app.',
        'Bank safety information is available on our website.',
        'Your OTP is 123456.',
        'We sent a verification code to your phone.',
        'The cashier entered a PIN at the counter.',
        'Hi, see you at the office tomorrow.',
        'Please review your latest bill in the app.',
        'Your delivery arrives on Tuesday.',
        'Apka jazzcash account ban gaya, mubarak ho.',
        'HBL se raqam transfer ho gai hai.',
        'Apki payment receive ho gai.',
        'Apna account app ma check karlo.',
        'aaj mausam bohat acha hai',
        'OTP ka matlab one time password hai.',
        'PIN code mein 4 digits hote hain.',
        'Bank ka password strong hona chahiye.',
        'آپ کا اکاؤنٹ فعال کر دیا گیا ہے۔',
        'آپ کے اکاؤنٹ میں رقم جمع ہو گئی ہے۔',
        'بینک کی نئی ایپ آج دستیاب ہے۔',
        'او ٹی پی ایک حفاظتی کوڈ ہے۔',
        'آج ہماری ملاقات طے ہے۔',
        'آج میری کلاس کا وقت بدل گیا ہے۔',
    ]
    # Extra balanced neutral templates so brand/prefix is never itself a class.
    for prefix in roman_prefix:
        for base in other[:11]:
            other.append((prefix + ' ' + base).strip())
    add('other',other)
    # Prevent duplicate messages from becoming heavier votes.
    unique = {}
    for message,label in examples:
        key = message.casefold().strip()
        if key in unique and unique[key][1] != label:
            raise AssertionError('Conflicting labels for a training example')
        unique[key] = (message,label)
    rows = list(unique.values())
    random.Random(SEED).shuffle(rows)
    return rows


def train():
    records=get_development_examples()
    messages, labels = zip(*records)
    model = make_pipeline(
        TfidfVectorizer(analyzer='char', ngram_range=(2, 5), sublinear_tf=True, max_features=28000),
        LogisticRegression(C=4, max_iter=1000, class_weight='balanced', random_state=SEED),
    )
    model.fit(messages,labels)
    MODEL_PATH.parent.mkdir(parents=True,exist_ok=True)
    joblib.dump(model, MODEL_PATH,compress=3)
    print('Trained intent AI from',len(records),'DEVELOPMENT examples;',MODEL_PATH.name,MODEL_PATH.stat().st_size,'bytes')
    for sentence in [
       'apka jazzcash accoutn bngya ha mubarak ho apna pin ya otp ksi kay sath share na krna',
       'OTP ksi ko na bhejna',
       'Jazzcash me account ban gaya, apna pin hme send kro',
       'Never share your OTP but send it to our agent now',
       'اپنا او ٹی پی کسی کو نہ بتائیں',
       'Your wallet balance is 10000 rupees',
    ]:
        pp=model.predict_proba([sentence])[0]
        print(model.predict([sentence])[0], f'{max(pp):.3f}', sentence)

if __name__=='__main__': train()
