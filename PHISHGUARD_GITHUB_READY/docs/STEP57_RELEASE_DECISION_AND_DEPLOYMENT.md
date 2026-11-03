# PhishGuard-PK | Source-data integration and release decision

## What changed in product code

- `phishguard/pakistan_rules.py`: catches urgent bank-account-block notices that direct users to a private 03xx number. Does not flag ordinary ATM activity notifications as the same scam.
- `phishguard/api.py`: adds verified aggregate research evidence to `/research-status` and tells `/model-status` that URL-Phish 2026 candidate is **research-only**.
- `phishguard/web/app.js`: updates the existing expandable research panel with latest dataset audit limitations. No layout redesign or change to mobile, hero, logo, PDF, CSV or normal scoring.
- `phishguard/url_ml_research.py`: consistent offline feature extractor with no outbound network calls.
- `scripts/step57_train_urlphish.py`: reproducible 2026 URL-Phish baseline (domain-disjoint split), NOT automated production deployment.
- `models/urlphish_2026_RESEARCH_ONLY.joblib`: non-production research candidate, **not referenced by the live Analyzer**.
- `evaluation/STEP57_SMS1000_SOURCE_AUDIT.json`: aggregate workbook audit only, **no original messages or phone numbers**.
- `evaluation/STEP57_URLPHISH_RESEARCH_RESULTS.json`: source-labelled URL benchmark including failed deep-link safety checks.
- `docs/STEP57_2026_DATASETS_AND_REPO_AUDIT.md`: source provenance, reuse rights and scientific limits.

## Tested

- All existing project tests plus seven new dataset integration tests: **159 passed, 2 existing skipped**.
- No accepted evidence justifies replacing the current experimental URL structural screening with the URL-Phish candidate. It would flag too many plausible ordinary deep links.
- No changes to external Vercel environment, GitHub branch, production credentials or current running website were made.

## Release procedure, when repository write access exists

Only if the GitHub branch has not changed since the earlier Step54 release:

1. Extract `PhishGuard_Step57_Code_Update_GitHub.zip`.
2. In GitHub folder `PHISHGUARD_GITHUB_READY`, upload/merge its `phishguard`, `scripts`, `models`, `evaluation`, `tests`, `docs` subfolders. Do not nest a second `PHISHGUARD_GITHUB_READY`.
3. Commit. Confirm Vercel production `Ready`. Verify `/health`, `/research-status`, `/model-status`, header logo, mobile textarea, `/analyze`, CSV batch and PDF export.
4. Roll back if any error. `models/urlphish_2026_RESEARCH_ONLY.joblib` must NEVER be renamed to `url_model_real.joblib`.

**Important:** The assistant has no connected GitHub write authorization here, and has **not** published or deployed these files. Upload/deployment verification needs an authorized repository write pathway. A ZIP link is not a production update.

## Research completeness versus working product

The functional online demo is implemented. The university's research claims are **not** fully satisfied: 50–100 genuinely collected and independently reviewed unseen SMS across all three languages/classes, adequate Urdu Fraud samples, independently verified low-false-positive URL ML validation, and final supervisor approval remain unavailable. Public source labels and synthetic examples cannot be silently treated as such evidence.
