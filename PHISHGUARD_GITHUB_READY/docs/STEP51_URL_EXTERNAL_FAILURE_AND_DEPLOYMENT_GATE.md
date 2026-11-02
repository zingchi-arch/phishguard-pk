# Step 51 | External URL model failure and safe release decision

**Date:** 2026-11-02. **Release state:** `BLOCKED`. **Live website:** remains on offline structural URL policy. **Model weights:** not to be deployed.

## Evidence: uploaded Step 50 Colab results

| Indicator | Value | Interpretation |
|---|---:|---|
| UCI source-labelled 2024 URLs | 9,999 usable before external-group holdout exclusions | Not 2026 Pakistan ground truth |
| Domain-disjoint training / validation / testing | 6,906 / 1,447 / 1,532 | No registered-domain overlap reported |
| Chosen model | lexical_random_forest, threshold 0.40 | Selected on UCI validation only |
| UCI test accuracy | 0.9961 | Historical source-label agreement only |
| UCI phishing recall | 0.9950 | Does not prove current phishing recall |
| OpenPhish publisher-labelled distinct hosts | 245 | Provider source, not manually authenticated |
| OpenPhish warnings | 245/245 | High coverage on this publisher sample |
| Tranco popular-domain homepage proxies | 400 | NOT human-certified legitimate |
| Tranco warnings | **400/400** | Extreme benign-proxy warning failure |
| Known normal reference URLs warned | 10/30 | Also concerning |
| Publisher errors | None reported | Downloads succeeded |
| Approval | **false** | Never ship model weights to Vercel |

## Technical decision

1. A high held-out score on UCI is not adequate because the 2026 external sample gives severe distribution shift.
2. The current live structural URL checker is also **not reliable as a phishing detector**: previous 2026 OpenPhish sample produced 1/245 warnings. The public interface must remain a **development risk indicator**, not a safety guarantee.
3. The release gate in `scripts/step51_url_release_gate.py` reads the exact original Step 50 JSON, checks diagnostic warning rates and always requires further independent adjudication. It cannot approve production from OpenPhish provider labels and Tranco popularity alone.
4. No suspicious URL is opened, resolved, rendered, or fetched by this release gate.
5. Do not upload `STEP50_MODEL_RESEARCH_ONLY.joblib` to `models/` or remove the `DO_NOT_DEPLOY` restriction.

## Full production readiness evidence still needed

- Independently vetted, dated, recent legitimate AND malicious URLs with consent/legal provenance.
- Domain/template-disjoint, large external test with acceptable false-positive and phishing recall rates, with confusion matrix.
- Risk-score calibration and abstention/uncertainty policy.
- Reviewed Pakistan-specific bank, BISP, prize, courier and challan scenarios.
- Independently adjudicated 50–100 real, unseen, balanced messages and representative Urdu Fraud coverage.

## Reproduce

```bash
python scripts/step51_url_release_gate.py --results evaluation/STEP50_EXTERNAL_RESEARCH_RESULTS.json
```

**Expected exit status: 2**, because deployment is blocked. For unit tests: `PYTHONPATH=. pytest -q`.

Data source: user-provided `PhishGuard_Step50_External_Model_Results.zip`, timestamp 2026-11-02T16:02:06Z, `STEP50_RESULTS.json`. Original source pages: UCI 967, OpenPhish public_feed, Tranco list V354N. This summary makes no claim about the actual safety of any domain.
