# PhishGuard-PK | Step 49, Independent-source URL diagnostic

**Research status: UNVERIFIED for deployment, no real-world accuracy claim.**

## What was actually performed on 2 November 2026

- Checked the official OpenPhish Community Feed description: updates every 12 hours, limited free list, no brand verification metadata. Source: https://openphish.com/phishing_feeds.html
- Checked PhishTank developer docs: `online-valid` is community-verified phishing evidence, but automatic bulk access may be rate-limited without an application key. Source: https://phishtank.org/developer_info.php
- Checked the Tranco research rank and the November 1, 2026 list **V354N**. This is a ranked popularity proxy, NOT a list of certified harmless webpages. Source: https://tranco-list.eu/list/V354N/1000000
- Extracted the first **40 URL examples in the OpenPhish feed page response** (lines 0-39 of the web snapshot). They represented **32 distinct hostnames** after host-level deduplication. **0/32 scored >=45** under `phishguard.url_policy.assess_url`. This is a *convenience sample*, not independently confirmed true current phishing URLs or statistically generalizable real-world sensitivity. Importantly, **NO candidate URL was contacted**.
- The current detector is an intentionally conservative **structural indicator**, not a supervised phishing classifier or probability. Its lack of warnings on most feed examples is a safety/usability limitation and a reason to avoid making a reliability claim.

## Engineering change

New script `scripts/step49_external_url_evaluation.py` and accompanying one-click **research-only** Colab notebook:

1. Downloads ONLY the public **publisher data URLs** from OpenPhish and dated Tranco. It never downloads, opens, or resolves URLs *listed inside* them.
2. Deterministically samples host-diverse OpenPhish entries and top-100k Tranco domains.
3. Runs `assess_url` with pre-existing thresholds 45 (caution) and 75 (strong warning); thresholds are not optimized on the evaluated records.
4. Writes **hashes** of URLs and hosts with indicators and aggregate counts, not usable phishing URLs.
5. Reports partial/unavailable sources explicitly, without silently substituting synthetic or older data.

The OpenPhish set can estimate source-feed warning rate, **not representative global recall**. Tranco homepage screening can reveal false warning issues on popular root domains, **not an authenticated benign false-positive rate**. These cohorts have very different URL structure and possible source-selection biases, so **do not compute an accuracy, F1, or ROC AUC by pairing them**.

## How to run

Offline with local, downloaded publisher data:

```bash
python scripts/step49_external_url_evaluation.py \
  --phishing-file PRIVATE_openphish_feed.txt \
  --proxy-file PRIVATE_tranco_V354N.csv \
  --output PRIVATE_step49_results
```

Or publisher download (internet access required):

```bash
python scripts/step49_external_url_evaluation.py --download --output PRIVATE_step49_results
```

**No GitHub upload of raw publisher URLs, visitor SMS, patient/bank records, or private evaluation results.** The notebook exports only summary and hashed case diagnostics.

## University status, real blockers

- Dataset source provenance is not the same as 3,000-5,000 independently approved multilingual three-class training labels.
- Urdu Fraud and Roman Urdu normal messages have not been sufficiently independently reviewed.
- The required 50-100 truly independent, permissioned, unseen SMS test set has **NOT** been collected or evaluated. Synthetic examples and source-labelled samples do not substitute for it.
- Supervised URL model has **NOT** passed independent legitimate deep-link false-positive and recent phishing testing. Live URL ML remains disabled.
- No final 2026 Pakistan URL accuracy or real-world scam recall is claimed.

## Decision

**NO_MODEL_DEPLOYMENT.** Preserve the conservative live structural checker and keep the research pipeline separate. Complete independent data collection, source authentication, model comparison and a supervisor-approved holdout before shipping any URL classifier.
