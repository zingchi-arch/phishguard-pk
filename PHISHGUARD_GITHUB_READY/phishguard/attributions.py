"""Bounded, opt-in, local token deletion evidence for the TEXT classifier.

This is not SHAP or LIME. It measures the difference in the development
classifier's Scam-class score after removing one whitespace token at a time.
It cannot explain sender verification, URL structural rules, risk floors, or
an ultimate fraud determination. It makes NO external/network requests.
"""
from __future__ import annotations

import re
import numpy as np

MAX_MESSAGE_CHARS = 900
MAX_TOKENS = 16


def explain_text_deletions(text_model, message: str, *, max_tokens: int = MAX_TOKENS) -> dict:
    """Return positive and negative shifts in Scam-class model score (percentage points).

    Output is a *local sensitivity diagnostic*, not a probability of actual scam.
    This endpoint is purposefully separate from the ordinary analyze/batch flow.
    """
    if not isinstance(message, str) or not message.strip():
        raise ValueError('Message must contain text.')
    if len(message) > MAX_MESSAGE_CHARS:
        raise ValueError(f'For model explanation use at most {MAX_MESSAGE_CHARS} characters.')
    max_tokens = max(1, min(MAX_TOKENS, int(max_tokens)))
    matches = list(re.finditer(r'\S+', message))
    if not matches:
        raise ValueError('No words to explain.')
    # Spread attribution across the message instead of silently ignoring the end.
    if len(matches) > max_tokens:
        indexes = sorted(set(round(i * (len(matches) - 1) / (max_tokens - 1)) for i in range(max_tokens))) if max_tokens > 1 else [0]
    else:
        indexes = list(range(len(matches)))
    classes = [str(c) for c in text_model.classes_]
    if 'Scam' not in classes:
        raise ValueError('The text classifier has no Scam class.')
    target_idx = classes.index('Scam')

    # Only the submitted text and the bounded list of perturbed variants are analyzed.
    variants = [message]
    for i in indexes:
        m = matches[i]
        variants.append((message[:m.start()] + ' ' + message[m.end():]).strip())
    raw = np.asarray(text_model.predict_proba(variants), dtype=float)
    if raw.shape != (len(variants), len(classes)) or not np.isfinite(raw).all():
        raise ValueError('Invalid model score matrix for explanation.')
    base = float(raw[0, target_idx])
    impacts = []
    for row_index, token_index in enumerate(indexes, start=1):
        token = matches[token_index].group(0)
        delta = (base - float(raw[row_index, target_idx])) * 100.0
        impacts.append({
            'token': token,
            'position': token_index,
            'change_in_scam_model_score_points': round(delta, 3),
            'interpretation': 'raises_Scam_model_score' if delta > 0.05 else ('reduces_Scam_model_score' if delta < -0.05 else 'negligible_effect'),
        })
    increases = sorted((r for r in impacts if r['change_in_scam_model_score_points'] > 0.05),
                       key=lambda r: -r['change_in_scam_model_score_points'])[:6]
    decreases = sorted((r for r in impacts if r['change_in_scam_model_score_points'] < -0.05),
                       key=lambda r: r['change_in_scam_model_score_points'])[:4]
    return {
        'method': 'local_token_deletion_NOT_SHAP_OR_LIME',
        'score_explained': 'development_text_classifier_Scam_class_only',
        'original_scam_class_model_score_percent': round(base * 100, 2),
        'token_count': len(matches),
        'tokens_tested': len(indexes),
        'positive_evidence': increases,
        'negative_evidence': decreases,
        'limitations': ('Perturbation sensitivity, not causal evidence, SHAP, LIME, or calibrated risk. '
                        'It does not account for URL policy, sender verification, Pakistani risk floors, '
                        'or interactions between words; removing a word can produce unnatural text.'),
    }
