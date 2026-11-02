# Step 47: Honest evidence and defense protocol

## What has been completed

- Public demo with FastAPI, multilingual screening, offline URL structural checks and opt-in model token-deletion explanations.
- Naive Bayes, SVM, Random Forest and separate XLM-R research experiments, all on provisional/source labels.
- Actual offline SHAP sample; LIME research script prepared, runtime verification not complete.
- Step47's 100-record **source-category proxy** selects Step41 source-designated TEST records, anonymizes output, and records gaps.

## What Step47 does NOT establish

- Human-reviewed, genuine 50-100-message external evaluation. The 100-record source proxy is **not** a substitute.
- Three-class labels verified across English, Roman Urdu and Urdu; source categories are not equivalent to final verdicts.
- Urdu-script Fraud recall; Urdu-source test has no Fraud examples.
- Absence of training overlap, because the full training corpus is not available in the current repository snapshot.
- Accuracy on current scams, model calibration, or reliable benign URL false alarm rates on an external corpus.

## Real independent test protocol (unskippable academic requirement)

1. With permission, obtain **50-100 actually observed, previously unused** messages, or publicly published examples with reusable citations. Redact recipient names, CNIC, account numbers, full phone numbers and personal links.
2. Log source date, medium, provenance URL/document, reuse rights, and reviewer. No teacher-generated templates in this set.
3. Have someone other than the model developer independently review each message and write Safe/Suspicious/Scam and language. Keep source label separate from final verdict. Disagreements or uncertain cases remain `Unclear` until adjudicated.
4. Compare normalized message text and template families against ALL development datasets, plus external-source overlap; if the corpus is missing, do NOT claim verified independence.
5. Use the established `scripts/step45_independent_test_gate.py` on the final labelled CSV and a COMPLETE development corpus. It will check metadata but cannot prove claimed consent or human identity.
6. Run frozen production model once, produce confusion matrices, macro-F1, Scam recall, per-language error analysis, and report uncertainty and representative sample limitations.
7. Keep private SMS and identifiable screenshots OUT of the public GitHub. Publish only aggregated metrics, redacted examples, source bibliographies and methods.

## Final dissertation/viva checklist

The university PDF's ten original requirements remain the authority. Do not describe the project as independently validated or a commercially verified anti-phishing product. Distinguish weak/source labels, synthetic QA, and separately reviewed real-world evidence on every slide.
