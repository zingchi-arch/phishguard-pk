# PhishGuard-PK | Step 53 | Website Repair + New Research Audit Sync

**Source:** User's actual repository download `phishguard-pk-main.zip`, November 3, 2026. Only changed files are in the deployment patch.

## Completed repairs

1. **Mobile tap/zoom fix:** The textarea font was 14px on desktop and **13px on mobile**, triggering focus auto-zoom on iPhone Safari. The actual form textarea and CSV file input now have a minimum 16px font, and `touch-action: manipulation`. The standard viewport meta remains unchanged, **user pinch zoom remains available**. No `user-scalable=no` / `maximum-scale=1` workaround.
2. **Missing web assets:** FastAPI previously returned 404 for the JavaScript animation `/motion.js`, built-in PDF exporter `/pdf-report.js`, and `/assets/...` URLs. Added same-origin first-party routes and a static asset mount. PDF export and hero image requests now have working server routes.
3. **Link safety transparency:** Every URL analysis now contains `url_verification_status=NOT_VERIFIED_OFFLINE_ONLY`; each parsed URL includes `url_authenticity=NOT_VERIFIED`. The analyzer still never opens, fetches or authenticates a destination. A prominent yellow notice appears whenever URLs are present, even if the overall verdict is `Safe`. PDF report uses **URLs screened offline**, not *inspected*.
4. **Optional real text-model evidence:** Users may click **Explain text model (experimental)** for inputs up to 900 characters, except URL-only analysis. This calls the existing `/analyze/explain` API. It displays local token-deletion score sensitivity, **not SHAP or LIME**. This does not replace the rule explanations or score.
5. **Newest research, honestly labeled:** New `/research-status` endpoint reads `evaluation/STEP50_EXTERNAL_RESEARCH_RESULTS.json` and `evaluation/STEP51_RELEASE_GATE_FAIL.json` already in the user-supplied repository. It surfaces two provider/proxy research indicators in an expandable Research disclosure. The website clearly marks experimental URL ML **NOT DEPLOYED**.
6. **Stale-result handling:** Editing the input clears an earlier result, hides its PDF export, and invalidates in-flight analysis so outdated results cannot be mistaken for new input.
7. **Existing aesthetic retained:** Header, hero images, animation design, palette, responsive sections and copy largely untouched. Only the analyzer safety note, research disclosure and explanation controls were added.

## What was deliberately NOT deployed

- **Step50 research URL Random Forest** that warned on 400/400 Tranco homepage proxies (popular domains, not adjudicated safe). Its UCI source-labelled 99.61% is NOT independent real-world accuracy.
- Any unapproved URL weights, downloaded phishing URLs, private messages or synthetic bulk training data.
- Any unverified XLM-R model for production text predictions.

## Verification in this project

- Full Python suite: **152 passed, 2 existing skips**, tested on the extracted user repository.
- `node --check` passed for the UI JS and PDF JS.
- FastAPI `TestClient` checks `/`, `/styles.css`, `/app.js`, `/motion.js`, `/pdf-report.js`, the site images under `/assets/`, `/analyze`, `/analyze/batch`, `/analyze/explain` and `/research-status`.
- Browser navigation was blocked in this workspace; **real iOS Safari and Vercel deploy testing still required**. Do not claim that the public deployed website has already changed.

## How to deploy one patch

1. Extract **`PhishGuard_Step53_Website_GitHub_Patch.zip`**.
2. Open `https://github.com/zingchi-arch/phishguard-pk/tree/main/PHISHGUARD_GITHUB_READY`.
3. Inside the extracted `PHISHGUARD_GITHUB_READY`, upload **`phishguard`**, **`tests`**, **`docs`** folders to that **same** GitHub folder. Make sure final paths look like `PHISHGUARD_GITHUB_READY/phishguard/web/styles.css`, not a duplicate nested `PHISHGUARD_GITHUB_READY/PHISHGUARD_GITHUB_READY/`.
4. Commit changes. Confirm the linked Vercel deployment says **Ready**.
5. On iPhone Safari and Android Chrome, open the latest website, tap the textarea and CSV chooser, type and analyze an ordinary message and a suspicious example URL; check that focus doesn't unexpectedly zoom and link-not-verified notice shows. Test Download PDF and desktop Batch CSV.
6. If the live site does not change, clear the browser cache / use an incognito tab and confirm Vercel is serving the latest GitHub commit. If errors appear, rollback to previous working commit.

## Outstanding academic requirements

The independent 50–100 genuine reviewed SMS holdout, representative Urdu scam evidence, and valid external supervised URL ML approval are still pending. This website patch **does not pretend those requirements are complete**.
