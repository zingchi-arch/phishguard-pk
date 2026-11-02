# PhishGuard-PK | Step 43, Engineering Fix and Research Benchmark

Date: 2026-11-02. Repository module: `PHISHGUARD_GITHUB_READY`.

## Changes actually implemented

1. **Urdu scam detection:** Urdu-script BISP (بی آئی ایس پی), cash assistance redirection, Urdu Jeeto Pakistan/gold, Roman Urdu OTP requests, Urdu e-challan payment links and FIA arrest/payment threats. These are offline risk indicators, not proof of scam or sender authentication.
2. **Negation and false positives:** Separate `Never share OTP` safety advice from a later `Send your PIN` demand, instead of exempting an entire message due to one negation. Pure social Eid/Jummah greetings with no external links, money, threat, prizes or credentials are guarded against synthetic-model false alarms. A linked or financial message never receives that greeting override.
3. **Model experiments:** Character + word TF-IDF with Linear SVM compared on held-out **source labels** against an existing character-only SVM. Selection was based on validation macro F1. No unverified model was added to the public backend.
4. **Automated checks:** 69 passed, 2 existing skips. New negative and positive tests are marked as **authored QA**, NOT independently received SMS.
5. **No website design or production model changed.** GitHub code patch can be applied separately after review. Existing live Vercel deployment is unchanged until the user uploads the patch.

## Source-category experiment, not production verification

| Metric | Prior SVM | Step43 hybrid SVM |
|---|---:|---:|
| Previously examined 878-example source-labelled test agreement | 95.67% | 96.47% |
| Roman Urdu agreement, 146 examples | 78.77% | 81.51% |
| Fraud recall, 220 source-labelled examples | 98.18% | 98.64% |

The validation gains are marginal (previous macro F1 0.9212; hybrid 0.9218). The test set was examined in Steps 41/42 and is **not an untouched blind set**. Results are **not 96% real-world security accuracy**. Zero verified Urdu-script fraud examples are in this test. Original datasets have independently unverified individual-message provenance. The teacher's synthetic corpus remains excluded from external evaluation.

**Do not deploy research source-category model as the Safe / Suspicious / Scam classifier.** `Normal/Promotional/Fraud` is a different label space from the product's three verdicts.

## Current application readiness

| Original university item | Status | Reason |
|---|---|---|
| 1. Multilingual 3-class verified dataset | Pending | 11,313 candidates, 0 independently verified message labels; Urdu Fraud gap |
| 2. Multilingual preprocessing | Implemented, provisional | Urdu and Roman normalization, TF-IDF, tests |
| 3. NB, SVM, RF, XLM-R | Experimental training completed | Source categories; XLM-R LoRA trained separately; deployment blocked |
| 4. URL AI | Experimental, not approved for production | Earlier high false-positive rate on legitimate links |
| 5. Combined score | Implemented, uncalibrated | Risk indicator and rule floors need external calibration |
| 6. SHAP/LIME | Offline SHAP script available | Full live explanation fidelity not certified |
| 7. API backend | Implemented, tested | FastAPI and batch; abuse/rate-limit deployment hardening pending |
| 8. Website | Existing working prototype | No UI redesign; upload code patch separately if desired |
| 9. 50-100 truly unseen real SMS | Pending | Consent, provenance, independent reviewer labels needed |
| 10. Docs, report, code and viva | Partly implemented | Final evidence-backed report requires items 1, 4, 6, 9 |

## Reproduce locally

Inside project directory:

```bash
python -m pytest -q
python run_web.py
```

These results concern a **development screening application**. A displayed sender ID may be spoofed. A `Safe` verdict never proves authenticity. The server never fetches the message's URLs.

## Research reproduction

`MODEL_RESEARCH/RESEARCH_METRICS.json` documents selection and test. `RESEARCH_MODEL_NOT_FOR_WEBSITE.joblib` is a separate research artifact. Run `scripts/step43_hybrid_source_benchmark.py` with project on `PYTHONPATH`, the included source-labelled CSV and baseline .joblib from Step41 to reproduce.
