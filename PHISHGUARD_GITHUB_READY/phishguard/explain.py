"""Readable model evidence; optional LIME/SHAP in scripts/explain_shap.py."""
import re
from .preprocessing import normalize_message
from .message_intent import interpret_secret_intent

PATTERNS = {
 'Urgent action or threat':r'\b(urgent|immediately|foran|abhi|band|blocked|suspend|last chance|فوراً|فوری|بند|معطل)\b',
 'Prize, reward or unexpected payment':r'\b(prize|winner|reward|bonus|lottery|inaam|mubarak|انعام|مبارک|رقم)\b',
 'Credential or verification request':r'\b(otp|pin|password|verify|tasdeeq|tasdiq|login|تصدیق|پاس ورڈ|پن|کوڈ)\b',
 'Bank or benefit impersonation':r'\b(bisp|ehsaas|bank|jazzcash|easypaisa|8171|بینک|احساس)\b',
}

def evidence_patterns(message):
    hits=[]
    intent=interpret_secret_intent(message)
    if intent.protective_only:
        return []
    for label,regex in PATTERNS.items():
        if label=='Credential or verification request' and intent.protective_advice and not intent.unsafe_secret_request:
            continue
        if re.search(regex,message or '',re.I|re.U):hits.append(label)
    return hits

def model_top_tokens(pipeline,message,predicted_label,limit=6):
    """For linear SVM only: local signed ngram contributions, NOT SHAP values."""
    try:
        estimator=pipeline.named_steps['classifier']
        vect=pipeline.named_steps['tfidf']
        # Multi-class LinearSVC scores are linear by class. Calibrated models not supported.
        coefs=estimator.coef_
        classes=list(estimator.classes_)
        idx=classes.index(predicted_label)
        vec=vect.transform([normalize_message(message)])
        terms=vect.get_feature_names_out()
        product=vec.multiply(coefs[idx]).tocoo()
        positives=sorted(zip(product.data,product.col),reverse=True)
        return [{'feature':str(terms[c]),'contribution':round(float(s),4)}
                for s,c in positives if s>0][:limit]
    except (KeyError,AttributeError,ValueError,IndexError):
        return []

def critical_rule_risk(message):
    """Conservative high-signal safety override for threats/credential harvesting.

    Returns (minimum risk, reason). NOT a fraud probability; no network activity.
    Avoid classifying ordinary OTP delivery alerts as fraud unless a request follows.
    """
    t=(message or '').lower()
    intent=interpret_secret_intent(message)
    if intent.unsafe_secret_request:
        return (85,'High-risk request to disclose OTP, PIN or password') if re.search(r'(prize|winner|inaam|urgent|immediately|blocked|block|abhi|مبارک|فوری)',t) else (70,'Sensitive account credentials requested; verify independently')
    # Protective messages are not an invitation to disclose credentials.
    # Do not use a global 'do not share' exemption: a later instruction to
    # pay, click, or claim a prize still needs assessment.
    if intent.protective_advice and re.search(r'https?://|www\.',t):
        if re.search(r'\b(?:pay|fee|deposit|transfer|claim|bhejo|jama)\b|فیس|رقم\s*جمع',t):
            return 65,'Security warning accompanied by a payment or claim link; verify independently'
        if re.search(r'\b(?:click|login|verify|submit|enter)\b|کلک\s*کریں|تصدیق\s*کریں',t):
            return 55,'Security warning redirects to a verification or login link; verify independently'
    if intent.protective_only:
        return 0,''
    bait=bool(re.search(r'(prize|lottery|claim|reward|win\b|winner|inaam|free money|bonus|bisp|ehsaas|انعام|مبارک|رقم|ایوارڈ|جیت|احساس)',t))
    threat=bool(re.search(r'(suspend|block|band ho|urgent|immediately|foran|abhi|frozen|blocked|آخری|فوری|فوراً|بند|معطل)',t))
    ask=bool(re.search(r'(send|share|submit|enter|provide|click|verify|login|bhej|karein|karo|kren|tasdeeq|تصديق|تصدیق|بھیج|فراہم|شیئر|درج|کلک|دیں|کریں)',t)) and not intent.protective_advice
    sensitive=bool(re.search(r'(otp|pin\b|password|bank detail|card number|cnic|account detail|verification code|one.time.password|او ٹی پی|پن|پاس ورڈ|بینک تفصیل|بینک تفصیلات|شناختی کارڈ|خفیہ کوڈ)',t))
    if intent.protective_advice and re.search(r'(?<!\w)(?:click|pay|deposit|claim|submit|login|fee|visit|کلک|جمع)(?!\w)',t) and (bait or threat):
        return 65,'Possible suspicious action alongside a security warning; verify independently'
    if ask and sensitive and (bait or threat):
        return 85,'High-risk pattern: reward/threat plus request for private account details'
    if ask and sensitive:
        return 70,'Sensitive information or login requested; verify independently'
    if ask and (bait or threat):
        return 65,'Urgency or unexpected reward combined with an instruction to act'
    return 0,''


def highlighted_terms(message):
    """Return exact keyword spans used by the readable pattern explanation."""
    found=[]
    if interpret_secret_intent(message).protective_only:
        return found
    for regex in PATTERNS.values():
        for match in re.finditer(regex,message or '',re.I|re.U):
            token=match.group().strip()
            if token.lower() not in {x.lower() for x in found}:found.append(token)
    return found[:12]
