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
from .attributions import explain_text_deletions, MAX_MESSAGE_CHARS

WEB = Path(__file__).resolve().parent / 'web'
app = FastAPI(
    title='PhishGuard-PK', version='2.0.0',
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
    return {'status':'ok', 'project':'PhishGuard-PK', 'version':'2.0.0',
            'mode':'development_unvalidated'}


@app.get('/model-status')
def model_status():
    root = Path(__file__).resolve().parents[1] / 'models'
    return {
        'version':'2.0.0',
        'language_support':['English','Roman Urdu','Urdu'],
        'text_model_available':(root/'text_model.joblib').exists(),
        'url_classifier_type':'Real-labeled RF' if (root/'url_model_real.joblib').exists() else 'Offline heuristic (not independently validated)',
        'advanced_transformer_trained':(root/'xlmr_development'/'config.json').exists(),
        'training_status':'provisional_labels_not_verified',
        'explainability_live':'opt_in_local_token_deletion_NOT_SHAP_OR_LIME',
        'explainability_research':'SHAP_and_LIME_offline_only_when_optional_dependencies_installed',
        'disclaimer':'Risk indicators, not calibrated fraud probabilities.',
        'research_status_endpoint':'/research-status'
    }


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
