"""Actual SHAP and/or LIME research explanations for the 3-class text model.

Local use only. Does not execute on public /analyze traffic, click links, or
claim that a SHAP/LIME explanation describes the final hybrid verdict.

Install OPTIONAL dependencies: pip install -r requirements-advanced.txt
Example:
  python scripts/step45_shap_lime_explain.py --method shap --message 'Claim your prize today'
  python scripts/step45_shap_lime_explain.py --method lime --message 'Apka account band hai'

Output includes user-submitted words; keep it private. Default path is gitignored.
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
from pathlib import Path
import numpy as np
import joblib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def save_rows(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    if rows:
        with path.open('w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)


def explain(message: str, method='shap', out_dir: Path | None = None,
            lime_samples=200, shap_evals=100):
    if not message or len(message) > 600:
        raise ValueError('Provide 1-600 characters for bounded offline research explanations.')
    if method not in ('shap', 'lime', 'both'):
        raise ValueError('Choose shap, lime or both.')
    model = joblib.load(ROOT / 'models' / 'text_model.joblib')
    classes = [str(c) for c in model.classes_]
    predicted = str(model.predict([message])[0])
    class_idx = classes.index(predicted)
    out_dir = Path(out_dir or Path.home() / 'phishguard_step45_private_explain')
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        'model': 'development_text_model.joblib',
        'source_labels': 'unverified_and_partly_synthetic',
        'predicted_text_class': predicted,
        'model_class_scores_percent': {cl: round(float(v)*100, 2) for cl, v in zip(classes,model.predict_proba([message])[0])},
        'explanation_target': f'text_classifier_{predicted}_class_score_NOT_final_hybrid_verdict',
        'method': method,
        'disclaimer': 'SHAP/LIME only explain model predictions locally, not ground-truth, sender identity, URL authenticity, or final rule-based verdict.',
    }
    if method in ('shap', 'both'):
        try:
            import shap
        except ImportError as e:
            raise RuntimeError('SHAP missing: pip install shap') from e
        # Same API as documented by shap: masker Text(regex) and Partition explainer.
        masker = shap.maskers.Text(r'\W+')
        explainer = shap.Explainer(model.predict_proba, masker,
                                  output_names=classes, algorithm='partition')
        values = explainer([message], max_evals=max(40, int(shap_evals)))
        tokens = [str(t) for t in values.data[0]]
        shap_values = np.asarray(values.values[0, :, class_idx], dtype=float)
        rows = [{'token':t, 'shap_contribution_to_predicted_class_score':round(float(s),6)}
                for t, s in zip(tokens,shap_values)]
        rows.sort(key=lambda r:abs(r['shap_contribution_to_predicted_class_score']),reverse=True)
        save_rows(out_dir / 'text_shap_tokens.csv', rows)
        summary['shap'] = {'tokens':len(rows), 'algorithm':'Partition SHAP', 'file':'text_shap_tokens.csv'}
    if method in ('lime', 'both'):
        try:
            from lime.lime_text import LimeTextExplainer
        except ImportError as e:
            raise RuntimeError('LIME missing: pip install lime') from e
        lime = LimeTextExplainer(class_names=classes, random_state=2026)
        explanation = lime.explain_instance(message, model.predict_proba,
                                            labels=(class_idx,), num_features=12,
                                            num_samples=max(100, min(800, int(lime_samples))))
        rows = [{'feature':word, 'lime_weight_predicted_class':round(float(weight),6)}
                for word,weight in explanation.as_list(label=class_idx)]
        save_rows(out_dir / 'text_lime_features.csv',rows)
        summary['lime']={'features':len(rows), 'samples':max(100,min(800,int(lime_samples))),
                         'file':'text_lime_features.csv'}
    (out_dir / 'methodology.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
    return summary


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--message', required=True, help='Local 1-600 character sample. WARNING: saved tokens may contain personal data.')
    ap.add_argument('--method', choices=['shap','lime','both'], default='shap')
    ap.add_argument('--output-dir',type=Path)
    ap.add_argument('--shap-evals',type=int,default=100)
    ap.add_argument('--lime-samples',type=int,default=200)
    args=ap.parse_args()
    print(json.dumps(explain(args.message,args.method,args.output_dir,args.lime_samples,args.shap_evals),indent=2))
