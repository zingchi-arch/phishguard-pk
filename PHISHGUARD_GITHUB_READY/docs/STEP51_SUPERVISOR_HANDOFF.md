# PhishGuard-PK | Supervisor handoff (02 Nov 2026)

## Demonstrable work (can show today)

- Working public site: https://phishguard-pk.vercel.app/
- GitHub source: https://github.com/zingchi-arch/phishguard-pk (`PHISHGUARD_GITHUB_READY`)
- English, Roman Urdu and Urdu demo user interface; FastAPI `/analyze`, `/analyze/batch`, `/analyze/explain`.
- Modular preprocessing, text classification, Pakistan scam rules and structural URL checker.
- Classical text ML research: NB, SVM, RF. XLM-RoBERTa LoRA was trained on GPU.
- SHAP offline research example; live opt-in deletion-sensitivity explanation (not SHAP).
- Research-based URL classifier separately trained and rejected by external reliability testing.
- Reconstructed project with Step 43 base + 44–50 research/code updates + Step 51 release gate: 152 passed, 2 existing skipped locally.

## Honest study findings

- Step 41 source-label SVM: 95.67% agreement on 878 test items; Roman Urdu 78.77%.
- Step 41 GPU XLM-R: 91.12% source-label agreement on 878; Roman Urdu 54.79%; only 3 Urdu test examples, all Normal.
- Step 47 100-message source-proxy challenge: 98/100; NOT independent ground truth.
- Step 50 URL RF: UCI 99.61%; OpenPhish warnings 245/245; Tranco homepage proxy warnings 400/400; REJECT deployment.
- Screenshots/test logs are software QA only; no real-world safety or calibration guarantee.

## Remaining blockers for completed academic acceptance

1. Signed/reviewed label rubric for Safe/Suspicious/Scam with source evidence and rights for 3,000–5,000 genuine multilingual messages.
2. Adequate genuine Urdu-script Scam examples and 50–100 independently reviewed, completely unseen new real messages.
3. Recent externally validated URL model with reasonable false-positive rate and provenance.
4. Independent SHAP or LIME live-interface verification, as required by supervisor, plus reviewer sign-off and final thesis formatting.

## Suggested viva wording

"PhishGuard-PK is a functional research prototype with three-language interface, reproducible baseline and transformer experiments, a URL screening component, and explainable safety signals. External testing exposed unacceptable URL classifier false alarms, so we did not deploy that experimental model. An independent human-adjudicated real-world evaluation is still needed before performance certification."

**Do not claim** finished independent accuracy, complete Urdu scam recall, or deployment certification.
