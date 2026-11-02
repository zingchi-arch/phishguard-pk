# PhishGuard-PK | Step 49 review + Step 50 technical next action

## Uploaded Step 49 results (source-supplied, verified file integrity)

- Timestamp: `2026-11-02T15:44:37+00:00`
- **OpenPhish provider-labelled:** 245 unique-host URLs; **1** generated an indicator >=45 (**0.41%**). Not separately authenticated real-world recall.
- **Tranco top-100k popular-domain homepage proxies:** 400 URLs; **0** warnings >=45. Not a validated false-positive rate.
- URL records and hosts in CSV are only SHA-256 hashes; their raw values cannot be reconstructed from this ZIP.
- Publisher errors reported: `{}`.
- `645` hashed records: 643 score 8, 1 score 52, 1 score 33. Current structural detector effectively defaults to low indicator for almost every URL; that is NOT evidence of safety.

## New Step 50 local supervised research result (before fresh external test)

- Historical input: **10,000 UCI PhiUSIIL 2024 source-labelled URLs**, from previous user-supplied source dataset, not Pakistan-specific.
- Registered-domain separation: `libpsl_registrable_domain`; **train, validation and test groups do not overlap**.
- Selected model `char_tfidf_linear` using UCI validation; threshold `0.25`.
- UCI held-out: **1538** URLs; accuracy **99.74%**, phishing recall **99.48%**.
- **9/30** known legitimate references flagged at chosen threshold. That is poor external generalization; therefore **deployment blocked**.
- The UCI test set was not independently human-verified; the 99%+ score is **NOT** validated real-world or Pakistani phishing accuracy. Never write it as a product claim.
- No external OpenPhish/Tranco evaluation was possible locally because Step 49 ZIP intentionally contains *hashes only*, not raw URL strings. **Zero external predictions were fabricated.**

## One-click Colab Step 50

1. Upload `PhishGuard_Step50_URL_AI_ONE_CLICK.ipynb` to Google Colab.
2. Click **Runtime → Run all**. CPU is enough. No dataset upload.
3. The notebook fetches **only publisher feed files** (never phishing pages), trains two models, chooses threshold using historical validation alone, then reports new OpenPhish and Tranco results without tuning on them.
4. Upload its `PhishGuard_Step50_External_Model_Results.zip` back to this conversation.

The ZIP includes research model with **RESEARCH_ONLY** label and aggregate evidence. It does NOT install the model in live Vercel.

## Final university evidence STILL missing

- Independently verified real Pakistani URLs and genuine multilingual SMS, including Urdu Fraud.
- 50-100 independently reviewed out-of-training SMS examples with consent and class balance.
- End-to-end SHAP/LIME evidence, final calibration/false-alarm evaluation, write-up and viva verification.

## Original official source links

- UCI dataset 967: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
- OpenPhish feed repo: https://github.com/openphish/public_feed
- Tranco: https://tranco-list.eu/


## Step 50 locally replayed on older publisher/proxy reference samples

These are a **separate earlier** saved OpenPhish 40-URL sample and Tranco 30-domain sample, not the current Step 49 uploaded 245/400 hashes. Training excluded their registrable domains; threshold selected from UCI validation only.

- Historic OpenPhish provider-labelled warnings: **33/40**.
- Historic Tranco popularity-proxy warnings: **29/30**. This is a strong false-warning warning sign; no independent legitimacy authentication.
- UCI heldout rows after excluding all matching historic external-domain groups: 1429.
- **DEPLOYMENT BLOCKED**, even if historical UCI held-out score is high. The external samples are small and not representative.
