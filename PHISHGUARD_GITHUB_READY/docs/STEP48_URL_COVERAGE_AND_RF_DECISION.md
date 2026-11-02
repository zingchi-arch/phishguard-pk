# PhishGuard-PK | Step 48 | URL Coverage Reality Check

**Date:** 2026-11-02  
**Scope:** Offline evaluation against a previously collected 10,000-record UCI PhiUSIIL 2024 URL subset. No URLs were opened or requested. **Not** an independent 2026 Pakistan threat-intelligence evaluation.

## What we tested

The same dataset contains **5,000 source-labelled phishing** URLs and **5,000 source-labelled legitimate** URLs (`label_uci=0` means phishing; `label_uci=1` means legitimate). Current site uses conservative structural URL rules, not the previous unreliable supervised Random Forest (RF). We ran every record without interacting with any domain.

| URL detector | UCI phishing flagged (of 5,000) | Phishing missed | UCI legitimate false warnings (of 5,000) | Reused benign 30 false warnings |
|---|---:|---:|---:|---:|
| **Live structural rules, caution/high >=45** | 104 | 4,896 | 0 | 0 (previous Step44 check) |
| Historical RF, raw score >=0.50 | 4,925 | 75 | 30 | 10 |
| Historical RF, raw score >=0.90 | 4,462 | 538 | 4 | 7 |
| Historical RF, raw score >=0.99 | 1,837 | 3,163 | 0 | 0 |

**Critical research limitation:** The historical RF was trained on a sample from this **same UCI source** and its complete training-row manifest is unavailable. Row overlap between its training data and these 10,000 URLs cannot be independently ruled out. These comparisons are not genuine external test metrics. Thresholds were reviewed **after seeing outcomes**, so the 0.99 result is NOT a new, pre-registered independent result. The 30 benign URLs were reused across earlier steps, not blind.

**Interpretation:** A low structural indicator does not mean a URL is safe. The current policy misses many source-labelled phishing URLs, including domains without known brand or path signals. The research RF might help, but automatically enabling it would give damaging false alarms, such as legitimate GitHub/docs URLs.

## Step48 actual production-side fix

1. Detect `gov.pk` appearing inside another unrelated hostname (`gov.pk.verify-8171.example.invalid`).
2. Detect sensitive-action hostnames using hyphenated imitations of a known reference domain (`bisp-gov-pk.verify.example.invalid`, `hbl-com.verify.example.invalid`).
3. Retain proper dot-boundary handling for genuinely hosted `*.gov.pk` links and legitimate documentation pages.
4. Preserve existing 3-way text screening and modern website design. **No historical RF auto-activation.**

This is a limited structural correction, **not** a claim that supervised URL detection is complete.

## Reproduction

Use developer-approved source archives, NOT an untrusted model file:

```bash
python scripts/step48_url_benchmark.py \
  --input-zip /private/PhishGuard_PK_Expanded_Source_Data_Audit.zip \
  --model-zip /private/PhishGuard_Step28_Real_URL_Model_Results.zip \
  --output /private/step48_results
python -m pytest -q
```

Reports contain hashed URL identities and aggregated metrics. Keep original real URL dataset private or distribute only under source license/terms; never make bulk phishing links publicly clickable.

## University status / stop conditions

- **Technical URL RF experiment:** Exists from Step28, and compared again in Step48. Not approved for live decisions.
- **External URL validation:** **PENDING.** Needs genuinely independent 2025-2026 positive/negative URLs with sources, acquisition dates and rights, ideally >=100 of each, with domain and temporal separation from training. Do not visit suspected phishing domains just to verify them.
- **50–100 independent real SMS:** **PENDING.** Must include English, Roman Urdu, Urdu and Safe/Suspicious/Scam, with independent verification, privacy/consent and an actual training-overlap audit.
- **SHAP/LIME:** Offline SHAP executed in Step45; LIME run unverified.
- **Research honesty:** Never label Step47 98/100 source-proxy as human-independent accuracy, and never label this Step48 UCI comparison as live URL accuracy.
