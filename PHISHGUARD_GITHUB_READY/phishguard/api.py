"""Same-origin web application and documented JSON API.

The server never fetches links included in user messages, never writes submitted
messages to disk, and is intended for a controlled/local deployment until audited.
"""
from pathlib import Path
from typing import List
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from .inference import analyze_message

WEB = Path(__file__).resolve().parent / 'web'
app = FastAPI(
    title='PhishGuard-PK', version='2.0.0',
    description='Multilingual message + offline URL risk screening. Risk indicators are uncalibrated.',
)


# Browser-ready art assets; static files also qualify for Vercel CDN caching.
app.mount("/assets", StaticFiles(directory=WEB / "assets"), name="assets")

class MessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10000)

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
def motion():
    return FileResponse(WEB / 'motion.js', media_type='text/javascript',
                        headers={'Cache-Control': 'public, max-age=300', 'X-Content-Type-Options': 'nosniff'})


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
        'disclaimer':'Risk indicators, not calibrated fraud probabilities.'
    }


@app.post('/analyze')
def analyze(payload: MessageRequest):
    try:
        return analyze_message(payload.message)
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
