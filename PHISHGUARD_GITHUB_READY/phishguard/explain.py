"""Readable model evidence; optional LIME/SHAP in scripts/explain_shap.py."""
import re
from .preprocessing import normalize_message

PATTERNS = {
 'Urgent action or threat':r'\b(urgent|immediately|foran|abhi|band|blocked|suspend|last chance|فوراً|فوری|بند|معطل)\b',
 'Prize, reward or unexpected payment':r'\b(prize|winner|reward|bonus|lottery|inaam|mubarak|انعام|مبارک|رقم)\b',
 'Credential or verification request':r'\b(otp|pin|password|verify|tasdeeq|tasdiq|login|تصدیق|پاس ورڈ|پن|کوڈ)\b',
 'Bank or benefit impersonation':r'\b(bisp|ehsaas|bank|jazzcash|easypaisa|8171|بینک|احساس)\b',
}

def evidence_patterns(message):
    hits=[]
    for label,regex in PATTERNS.items():
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
    # Explicit education / protective messages should not activate this particular override.
    if re.search(r'(do not share|never share|don.t share|share na karein|mat bhej|مت بھیج|کبھی نہ|ہرگز نہ|خبردار)',t):
        return 0,''
    bait=bool(re.search(r'(prize|lottery|claim|reward|win\b|winner|mubarak|inaam|free money|bonus|bisp|ehsaas|انعام|مبارک|رقم|ایوارڈ|جیت|احساس)',t))
    threat=bool(re.search(r'(suspend|block|band ho|urgent|immediately|foran|abhi|frozen|blocked|آخری|فوری|فوراً|بند|معطل)',t))
    ask=bool(re.search(r'(send|share|submit|enter|provide|click|verify|login|bhej|karein|karo|kren|tasdeeq|تصديق|تصدیق|بھیج|فراہم|شیئر|درج|کلک|دیں|کریں)',t))
    sensitive=bool(re.search(r'(otp|pin\b|password|bank detail|card number|cnic|account detail|verification code|one.time.password|او ٹی پی|پن|پاس ورڈ|بینک تفصیل|بینک تفصیلات|شناختی کارڈ|خفیہ کوڈ)',t))
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
    for regex in PATTERNS.values():
        for match in re.finditer(regex,message or '',re.I|re.U):
            token=match.group().strip()
            if token.lower() not in {x.lower() for x in found}:found.append(token)
    return found[:12]
