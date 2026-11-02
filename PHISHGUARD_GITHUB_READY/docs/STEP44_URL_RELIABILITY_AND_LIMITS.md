# PhishGuard-PK | Step 44: URL structural risk fix

**Date:** 2026-11-02  |  **Scope:** Offline URL security screening, *not* a verified phishing URL classifier.

## Why this change was necessary

Previous experimental URL Random Forests scored **8 to 10 of 30 ordinary reference URLs** as high-risk, despite optimistic in-dataset scores. They also had uncertain labels and transfer to new real-world URLs. The live website did not ship those experimental RFs, but the original weak URL heuristic could miss `github.com.evil.invalid` or `bisp.gov.pk.fraud.invalid` because it mostly counted keywords and punctuation.

## Code changes

- New `phishguard/url_policy.py` performs **fully offline hostname-first checks**.
- Detects full reference domain embedded within an unrelated hostname, such as `github.com.evil.invalid` or `bisp.gov.pk.fraud.invalid`.
- Detects `@` userinfo confusion, URL shorteners, punycode names, questionable IP links and compound HTTP credential actions.
- **Does not auto-flag normal path keywords** such as a legitimate documentation `/account/` or `/login` path when the hostname is ordinary.
- Offline structural risk over 75 gets a high-priority risk floor, so a fake destination is not diluted by text-model output.
- Standalone URL input uses the URL structural indicator, not a synthetic-trained text classifier's URL-character artifacts.
- If an experimental RF file is accidentally present, it is shown for **diagnostics only**, never used in the user-facing decision. Its previous scores were not reliable enough for automatic activation.
- URLs are **never fetched**, no DNS queries, no click-through and no hostname ownership authentication. Displayed sender IDs are also never authenticated.
- UI/CSS/JavaScript and active text model **unchanged**.

## Reproducible QA results (not independent field evaluation)

`python scripts/step44_url_gate.py` produces offline test outputs using supplied local datasets.

| Check | Result | Meaning |
|---|---:|---|
| Known ordinary reference URL structures | 30 | Selected legacy examples, some illustrative URLs (e.g., YouTube ID) have not been verified to be live |
| High structural warnings among these references (indicator >=45) | 0 / 30 | In-sample regression check, not false-positive rate across the internet |
| Authored deceptive hostname test cases | 18 | All use `.invalid` reserved examples; NOT actual captured phishing URLs |
| Deceptive QA cases detected at >=75 | 18 / 18 | Developer-authored unit tests, not observed phishing recall |
| Python unit / API test suite | See current pytest output | Not a security certification |

**No independent real-world phishing recall, precision or F1 is established** by these tests. A page under a legitimate domain can be malicious, a fake can use an ordinary hostname, and any host can change after this check. A `Safe` display means **few structural warning signs**, not that a website is authenticated.

## Reference material (official destinations, NOT an allowlist)

The following official sites were checked on 2026-11-02 and used solely as **lookalike reference examples**. The code does not whitelist them or guarantee their pages safe:

- BISP `https://bisp.gov.pk/` and `https://8171.bisp.gov.pk/`.
- JazzCash `https://www.jazzcash.com.pk/contact-us/`.
- Meezan Bank `https://www.meezanbank.com/contact-us/`.
- HBL `https://www.hbl.com/` (security guidelines).
- Bank Alfalah `https://www.bankalfalah.com/`.

Official messages may legitimately contain links depending on the service; attackers can spoof sender IDs. HBL says not to open its banking links forwarded by SMS/email and never to share OTP or PIN by those channels. Always independently navigate to the organization's current official app or homepage.

## Explicitly pending original FYP requirements

1. **Reliable URL classifier:** A new independently reviewed and time-separated collection of phishing and benign URLs is still needed; do not call this heuristic a trained URL ML classifier. Earlier experimental RFs remain held outside production.
2. **50–100 independent real SMS evaluation:** External consent, provenance and human labels not yet collected.
3. **XLM-R full 3-language validation:** Urdu Fraud gap and Roman Urdu false alarms remain unresolved.
4. **SHAP/LIME:** Offline experiment script exists, user-facing explanations are currently patterns/structural reasons, not certified SHAP.
5. **Threshold calibration / rate limiting / final report:** Remain pending.

## GitHub deployment

Upload the files from the patch archive **to repository root** (the archive already includes `PHISHGUARD_GITHUB_READY/`). Do **not** overwrite `models/`, `data/` other than the two new QA files, or `phishguard/web/`. Existing website design is preserved.

For the user's repo with `PHISHGUARD_GITHUB_READY` open: enter that folder on GitHub, then drag the **contents of the patch's `PHISHGUARD_GITHUB_READY` folder**, not its outer directory. Commit once. Vercel will rebuild automatically if GitHub integration is active.

**Safety:** Static rules are advisory. Every review should be disclosed as a screening opinion rather than a proof of safe/malicious content.
