# Measured results, with limitations

- Training labels: **provisional source-derived and synthetic, NOT independently reviewed**.
- Corpus: 5,750 rows (including 213 synthetic).
- Grouped split: train 4088, validation 822, test 840 (roughly 70/15/15).
- Best model by **validation** macro F1: **Random Forest**.
- Weak-label holdout accuracy: **96.90%**. Do not quote without weak-label caveat.
- Weak-label holdout macro F1: **0.683**, recall macro: **0.681**.
- Suspicious-class F1 **0.105** on only 9 provisional test rows.
- Urdu holdout accuracy **44.4%**, n=18, largely synthetic.
- URL Random Forest fixture: synthetic only, ~1.00 test accuracy on generated samples; **does not generalize as evidence of real security detection**.
- SHAP output saved in `reports/shap_text_tokens.csv` and `reports/shap_url_features.csv`.

**Conclusions:** Functional architecture is demonstrated. The present data cannot support an independently verified real-world security performance claim. Before a final research conclusion, annotated Urdu/Suspicious data and real independent external test messages are required.
