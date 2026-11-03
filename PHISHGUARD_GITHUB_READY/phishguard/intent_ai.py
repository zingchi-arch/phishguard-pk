"""Free, local, open-source ML model for *message intent*, not sender identity.

This deliberately small scikit-learn model recognizes four DEVELOPMENT labels:
protect (safety advice), request (credential solicitation), mixed, other.
Its synthetic/development training examples are NOT real-world performance proof.
No message is sent to an AI provider, logged, or used for further training.
"""
from __future__ import annotations
from functools import lru_cache
from pathlib import Path
from dataclasses import dataclass
import joblib

MODEL_PATH = Path(__file__).resolve().parents[1] / 'models' / 'intent_ai_step59.joblib'
ENGINE_ID = 'step59-intent-hybrid-v1'

@dataclass(frozen=True)
class IntentPrediction:
    label: str
    score: float
    engine: str

@lru_cache(maxsize=1)
def _load_model():
    if not MODEL_PATH.is_file():
        return None
    # Bundled, project-authored artifact only. Never load user-supplied pickles.
    return joblib.load(MODEL_PATH)


def predict_message_intent(message: str) -> IntentPrediction:
    model = _load_model()
    if model is None:
        return IntentPrediction('unavailable',0.0,'not_loaded')
    probs = model.predict_proba([str(message or '')])[0]
    index = int(probs.argmax())
    return IntentPrediction(str(model.classes_[index]), round(float(probs[index]), 4), ENGINE_ID)
