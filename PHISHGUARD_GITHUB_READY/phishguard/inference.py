"""Combined text and URL analysis. Scores are indicative, not calibrated fraud probabilities."""
from pathlib import Path
import os
import joblib
import numpy as np
from .preprocessing import detect_language
from .urls import extract_urls, feature_vector, heuristic_url_risk, url_reasons, url_features
from .explain import evidence_patterns, highlighted_terms, model_top_tokens, critical_rule_risk
from .pakistan_rules import assess_pakistani_context, looks_like_plain_greeting
from .message_intent import interpret_secret_intent
from .url_policy import assess_url

MODEL_DIR = Path(__file__).resolve().parents[1] / 'models'
LABELS = ['Safe','Suspicious','Scam']
# Provisional decision boundaries, selected using the DEVELOPMENT validation split.
# Neither threshold nor risk indicator is a calibrated fraud probability.
SUSPICIOUS_THRESHOLD = 45.0
SCAM_THRESHOLD = 65.0

class Analyzer:
    def __init__(self, model_dir=MODEL_DIR):
        self.model_dir=Path(model_dir)
        self.text_model=joblib.load(self.model_dir/'text_model.joblib') if (self.model_dir/'text_model.joblib').exists() else None
        self.text_backend='classical'
        if os.environ.get('PHISHGUARD_TEXT_BACKEND','classical').lower()=='xlmr':
            from .transformer_adapter import TransformerPredictor
            self.text_model=TransformerPredictor(self.model_dir/'xlmr_development')
            self.text_backend='xlmr'
        self.url_model=joblib.load(self.model_dir/'url_model_real.joblib') if (self.model_dir/'url_model_real.joblib').exists() else None
        self.model_metadata = {}
        meta=self.model_dir/'model_metadata.json'
        if meta.exists():
            import json
            self.model_metadata=json.loads(meta.read_text(encoding='utf-8'))

    def analyze(self,message: str, sender_id: str | None = None, claimed_org: str | None = None):
        if not isinstance(message,str) or not message.strip():
            raise ValueError('Please enter a message.')
        if len(message)>10000:
            raise ValueError('Message must be at most 10,000 characters.')
        if self.text_model is None:
            raise RuntimeError('Model missing. Run: python scripts/train_all.py')
        language=detect_language(message)
        probabilities=self.text_model.predict_proba([message])[0]
        labels=list(self.text_model.classes_)
        raw_probs={lab:float(probabilities[i]) for i,lab in enumerate(labels)}
        probs={lab:raw_probs.get(lab,0.0) for lab in LABELS}
        # Development model signal: 100% * (Scam + 0.5 Suspicious).
        text_risk=100*(probs['Scam']+0.5*probs['Suspicious'])
        urls=extract_urls(message)
        url_results=[]
        url_rule_floor = 0.0
        for u in urls[:10]:
            # A high-scoring research RF is NOT allowed to overrule the URL policy:
            # previous host-separated testing showed 8-10/30 false alarms on
            # ordinary websites. Keep RF score diagnostic only if present.
            structural = assess_url(u)
            rf_score = None
            if self.url_model is not None:
                try:
                    rf_score = 100 * float(self.url_model.predict_proba([feature_vector(u)])[0][1])
                except (ValueError, IndexError, AttributeError):
                    pass
            indicator = structural.indicator
            if indicator >= 75 and structural.high_confidence_structure:
                url_rule_floor = max(url_rule_floor, 80.0)
            elif indicator >= 45:
                url_rule_floor = max(url_rule_floor, 45.0)
            url_results.append({'url':u, 'risk_indicator':float(indicator),
                'heuristic_indicator':round(heuristic_url_risk(u), 1),
                'real_data_rf_indicator':round(rf_score,1) if rf_score is not None else None,
                'url_structural_status':structural.status,
                'url_authenticity':'NOT_VERIFIED',
                'hostname_not_authenticated':structural.hostname,
                'features':url_features(u), 'reasons':list(structural.reasons)})
        url_risk=max((r['risk_indicator'] for r in url_results),default=0)
        # For a standalone URL input, ignore weak text-model artifacts on URL
        # characters. A low score still does NOT mean the site is authenticated.
        url_only = len(urls) == 1 and message.strip().rstrip('.,!?') == urls[0]
        if url_only:
            risk = float(url_risk)
        else:
            risk = 0.7 * text_risk + 0.3 * url_risk if urls else text_risk
        risk = max(risk, url_rule_floor)
        rule_floor,rule_reason=critical_rule_risk(message)
        pk_indicators=assess_pakistani_context(message,sender_id=sender_id,claimed_org=claimed_org)
        pk_floor=max((p.floor for p in pk_indicators),default=0.0)
        risk=max(risk,rule_floor,pk_floor)
        # The original synthetic classifier sometimes overflags Urdu greetings.
        # Only pure, no-link, no-action social greetings qualify. This is a
        # transparent heuristic guard, not model calibration or proof of safety.
        greeting_guard = looks_like_plain_greeting(message) and not urls and rule_floor == 0 and pk_floor == 0
        intent = interpret_secret_intent(message)
        # A clearly protective OTP/PIN notice should not be labelled Scam just
        # because the synthetic-data text model fires on OTP/PIN + bank words.
        # Never apply this cap when links or another risk rule are present.
        advisory_guard = (intent.protective_only and not urls and
                          rule_floor == 0 and pk_floor == 0)
        if greeting_guard or advisory_guard:
            risk=min(risk,39.0)
        risk=round(float(min(100,max(0,risk))),1)
        verdict='Scam' if risk>=SCAM_THRESHOLD else ('Suspicious' if risk>=SUSPICIOUS_THRESHOLD else 'Safe')
        clues=evidence_patterns(message)
        explanation=[]
        if advisory_guard:
            explanation.append(intent.reason)
        if greeting_guard:
            explanation.append('Ordinary personal greeting without a link, prize, payment or credential request; the sender is not authenticated.')
        if rule_reason: explanation.append(rule_reason)
        explanation.extend(p.reason for p in pk_indicators[:3])
        if clues: explanation.extend(clues)
        if url_results:
            explanation.extend(url_results[0]['reasons'][:3])
            explanation.append('URL checked by offline structural rules only. Link destination and legitimacy have NOT been verified; low score does not establish safety.')
        if not explanation: explanation.append('No strong pattern flags; classification is uncertain.')
        explanation.append('Indicative AI assessment only: verify through an official channel; never share OTPs or passwords.')
        return {'verdict':verdict,'risk_score':risk,'language_detected':language,
            'text_risk_indicator':round(float(text_risk),1),
            'safety_rule_floor':max(rule_floor,pk_floor),
            'pakistan_rule_ids':[p.rule_id for p in pk_indicators],
            'sender_authentication':'NOT_VERIFIED',
            'personal_greeting_guard_applied':greeting_guard,
            'security_advice_detected':intent.protective_advice,
            'security_advice_guard_applied':advisory_guard,
            'credential_request_detected':intent.unsafe_secret_request,
            'decision_thresholds':{'suspicious':SUSPICIOUS_THRESHOLD, 'scam':SCAM_THRESHOLD},
            'url_risk_indicator':round(float(url_risk),1) if urls else None,
            'url_model_status':'research_rf_diagnostic_not_in_decision' if self.url_model is not None else 'offline_structural_rules_unvalidated',
            'url_structural_rule_floor':url_rule_floor,
            'url_only_input':url_only,
            'url_verification_status':'NOT_VERIFIED_OFFLINE_ONLY' if url_results else 'NO_URL_PROVIDED',
            'text_backend':self.text_backend,
            'text_class_scores':{x:round(100*float(p),1) for x,p in probs.items()},
            'urls':url_results,'explanation':explanation,'highlighted_terms':highlighted_terms(message),'model_evidence':[],
            'disclaimer':'DEVELOPMENT SCREENING ONLY. No link is opened or verified. Indicators are not probabilities of phishing; source labels and Urdu samples remain insufficient for real-world accuracy claims.'}

_ANALYZER=None

def get_analyzer():
    global _ANALYZER
    if _ANALYZER is None: _ANALYZER=Analyzer()
    return _ANALYZER

def analyze_message(message, sender_id=None, claimed_org=None):
    return get_analyzer().analyze(message,sender_id=sender_id,claimed_org=claimed_org)
