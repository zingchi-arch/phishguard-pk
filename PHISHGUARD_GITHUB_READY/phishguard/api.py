"""Same-origin web application and documented JSON API.

The server never fetches links included in user messages, never writes submitted
messages to disk, and is intended for a controlled/local deployment until audited.
"""
from pathlib import Path
import json
from typing import List
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from .inference import analyze_message, get_analyzer
from .intent_ai import ENGINE_ID, MODEL_PATH as INTENT_MODEL_PATH
from .deep_ai import DEEP_AI_RELEASE, MODEL_ID as DEEP_MODEL_ID, MAX_DEEP_CHARS, is_configured, provider_config, analyze_with_deep_ai
from .attributions import explain_text_deletions, MAX_MESSAGE_CHARS

WEB = Path(__file__).resolve().parent / 'web'
app = FastAPI(
    title='PhishGuard-PK', version='2.3.0',
    description='Multilingual message + offline URL risk screening. Risk indicators are uncalibrated.',
)
# Serve all versioned first-party web assets from the actual app package.
# This fixes missing images, motion.js, and the offline PDF generator.
app.mount('/assets', StaticFiles(directory=WEB / 'assets'), name='assets')


class MessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10000)
    sender_id: str | None = Field(default=None, max_length=80, description="Optional sender label or number; never authenticated")
    claimed_org: str | None = Field(default=None, max_length=80, description="Optional organization claimed by the message; never authenticated")

    @field_validator('message')
    @classmethod
    def not_empty(cls, value):
        if not value.strip():
            raise ValueError('Message must not be empty')
        return value


class DeepMessageRequest(MessageRequest):
    consent_external_processing: bool = Field(default=False, description='User explicitly agrees to send best-effort redacted message data to the selected provider')


class BatchRequest(BaseModel):
    messages: List[str] = Field(min_length=1, max_length=100)

    @field_validator('messages')
    @classmethod
    def validate_each(cls, values):
        if any(not isinstance(x, str) or not x.strip() or len(x) > 10000 for x in values):
            raise ValueError('Each message must contain 1 to 10,000 characters')
        return values


@app.get('/', include_in_schema=False)
def home():
    return FileResponse(WEB / 'index.html', media_type='text/html',
                        headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})


@app.get('/styles.css', include_in_schema=False)
def styles():
    return FileResponse(WEB / 'styles.css', media_type='text/css',
                        headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})


@app.get('/app.js', include_in_schema=False)
def javascript():
    return FileResponse(WEB / 'app.js', media_type='text/javascript',
                        headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})


@app.get('/motion.js', include_in_schema=False)
def motion_script():
    return FileResponse(WEB / 'motion.js', media_type='text/javascript',
                        headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})


@app.get('/pdf-report.js', include_in_schema=False)
def pdf_script():
    return FileResponse(WEB / 'pdf-report.js', media_type='text/javascript',
                        headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})


@app.get('/health')
def health():
    return {'status':'ok', 'project':'PhishGuard-PK', 'version':'2.3.0',
            'release_id':ENGINE_ID, 'intent_ai_available':INTENT_MODEL_PATH.exists(),
            'mode':'development_unvalidated',
            'deep_ai_release_id':DEEP_AI_RELEASE, 'deep_ai_configured':is_configured(),
            'deep_ai_provider':(provider_config() or ('None', 'none'))[0]}


@app.get('/model-status')
def model_status():
    root = Path(__file__).resolve().parents[1] / 'models'
    return {
        'version':'2.3.0',
        'deep_ai_release_id':DEEP_AI_RELEASE,
        'deep_ai_configured':is_configured(),
        'deep_ai_model':(provider_config() or ('None', DEEP_MODEL_ID))[1],
        'deep_ai_provider':(provider_config() or ('None', 'none'))[0],
        'deep_ai_default':'OFF_EXTERNAL_CONSENT_REQUIRED',
        'deep_ai_privacy':'Best-effort redaction before sending to configured external AI provider; do not submit private information',
        'release_id':ENGINE_ID,
        'intent_classifier':'Local open-source scikit-learn char-ngram classifier (development examples, not a pretrained LLM)',
        'intent_ai_available':INTENT_MODEL_PATH.exists(),
        'language_support':['English','Roman Urdu','Urdu'],
        'text_model_available':(root/'text_model.joblib').exists(),
        'url_classifier_type':'Real-labeled RF' if (root/'url_model_real.joblib').exists() else 'Offline heuristic (not independently validated)',
        'advanced_transformer_trained':(root/'xlmr_development'/'config.json').exists(),
        'training_status':'provisional_labels_not_verified',
        'explainability_live':'opt_in_local_token_deletion_NOT_SHAP_OR_LIME',
        'explainability_research':'SHAP_and_LIME_offline_only_when_optional_dependencies_installed',
        'disclaimer':'Risk indicators, not calibrated fraud probabilities.',
        'research_status_endpoint':'/research-status',
        'urlphish_2026_research_candidate':(root/'urlphish_2026_RESEARCH_ONLY.joblib').exists(),
        'urlphish_2026_model_in_live_decision':False,
        'uploaded_sms_1000_training_status':'provisional_audit_only_no_unverified_label_autopromotion'
    }


def _latest_uploaded_dataset_status():
    """Aggregated research evidence only; never exposes original URL/SMS rows."""
    root=Path(__file__).resolve().parents[1]
    try:
        url=json.loads((root/'evaluation'/'STEP57_URLPHISH_RESEARCH_RESULTS.json').read_text(encoding='utf-8'))
        sms=json.loads((root/'evaluation'/'STEP57_SMS1000_SOURCE_AUDIT.json').read_text(encoding='utf-8'))
        return {
            'urlphish_records_after_dedup':int(url['rows']),
            'urlphish_same_source_accuracy':float(url['heldout_same_source']['accuracy']),
            'urlphish_phishing_recall':float(url['heldout_same_source']['phishing_recall']),
            'urlphish_constructed_deeplink_warnings':int(url['constructed_deep_path_warnings']),
            'urlphish_constructed_deeplink_probes':int(url['constructed_deep_path_probes']),
            'urlphish_url_model_live':False,
            'sms1000_research_records':int(sms['records']),
            'sms1000_urdu_script_records':int(sms['urdu_script_records']),
            'sms1000_independent_human_verified':False,
            'explanation':'URL-Phish is source-labelled research; SMS spreadsheet has provisional binary labels. Neither supplies the required verified 3-language, 3-class independent holdout.'
        }
    except (OSError, KeyError, TypeError, ValueError):
        return {'status':'research_dataset_summary_unavailable','urlphish_url_model_live':False}


@app.get('/research-status')
def research_status():
    """Expose source-labelled research *limitations*, not deployable accuracy.

    All metrics are drawn from the existing Step50 and Step51 project files.
    Never serve experimental model weights, raw SMS, or phishing URLs.
    """
    evaluation = Path(__file__).resolve().parents[1] / 'evaluation'
    try:
        source = json.loads((evaluation / 'STEP50_EXTERNAL_RESEARCH_RESULTS.json').read_text(encoding='utf-8'))
        gate = json.loads((evaluation / 'STEP51_RELEASE_GATE_FAIL.json').read_text(encoding='utf-8'))
        op = source['external_source_diagnostics']['openphish_provider_label']
        tr = source['external_source_diagnostics']['tranco_homepage_proxy']
        if source.get('deployment_approved') is not False or gate.get('production_approved') is not False:
            raise ValueError('The expected blocked release gate is not documented.')
        return {
            'status':'research_diagnostics_only',
            'structural_openphish_warnings':int(op['baseline_structural_45_warnings_n']),
            'openphish_source_urls':int(op['n']),
            'experimental_model_tranco_warnings':int(tr['warnings_n']),
            'tranco_popular_domains':int(tr['n']),
            'supervised_url_model_deployed':False,
            'real_world_independent_accuracy_verified':False,
            'url_source_caveat':'OpenPhish feed is provider-labelled; Tranco homepages are popularity proxies, not authenticated safe sites.',
            'sms_external_test_status':'50-100 independently reviewed real SMS benchmark pending',
            'latest_uploaded_dataset_status':_latest_uploaded_dataset_status(),
        }
    except (OSError, ValueError, KeyError, TypeError):
        return {'status':'research_evidence_unavailable', 'supervised_url_model_deployed':False,
                'real_world_independent_accuracy_verified':False}


@app.post('/analyze')
def analyze(payload: MessageRequest):
    try:
        return analyze_message(payload.message,sender_id=payload.sender_id,claimed_org=payload.claimed_org)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post('/analyze/deep')
def analyze_deep(payload: DeepMessageRequest):
    # An explicit affirmative signal is required. Never auto-send local traffic.
    if not payload.consent_external_processing:
        raise HTTPException(status_code=422, detail='You must opt in to Groq external processing for this request.')
    if len(payload.message) > MAX_DEEP_CHARS:
        raise HTTPException(status_code=422, detail=f'Deep AI supports at most {MAX_DEEP_CHARS} characters.')
    try:
        local = analyze_message(payload.message, sender_id=payload.sender_id, claimed_org=payload.claimed_org)
        return analyze_with_deep_ai(payload.message, local)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post('/analyze/batch')
def analyze_batch(payload: BatchRequest):
    rows = []
    for i, message in enumerate(payload.messages, 1):
        try:
            result = analyze_message(message)
            rows.append({'row':i, 'message':message, 'result':result})
        except (ValueError, RuntimeError) as exc:
            rows.append({'row':i, 'message':message, 'error':str(exc)})
    return {'count':len(rows), 'results':rows,
            'note':'Never treat these results as verified phishing determinations.'}


@app.post('/analyze/explain')
def explain_analysis(payload: MessageRequest):
    """Opt-in, bounded diagnostic for text classifier only; not SHAP/LIME.

    Kept separate from the fast regular/batch analyzer to avoid expensive
    inference on every user request. Links are NEVER fetched.
    """
    if len(payload.message) > MAX_MESSAGE_CHARS:
        raise HTTPException(status_code=422, detail=f'Explanation supports up to {MAX_MESSAGE_CHARS} characters')
    try:
        result = analyze_message(payload.message, sender_id=payload.sender_id, claimed_org=payload.claimed_org)
        if result['url_only_input']:
            result['model_attribution'] = {
                'status': 'not_applicable_to_url_only',
                'reason': 'A URL-only verdict uses structural URL policy, not the text classifier.'
            }
        else:
            result['model_attribution'] = explain_text_deletions(get_analyzer().text_model, payload.message)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
