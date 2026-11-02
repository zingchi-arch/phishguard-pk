# PhishGuard-PK | Step 46: End-to-End Regression & University Readiness

Date: 2026-11-02. This is a software quality update, **not** a validated fraud detection model.

## Verified locally

- `python -m pytest -q`: **121 passed, 2 skipped**.
- `python scripts/step46_e2e_suite.py`: **36 of 36 HAND-AUTHORED synthetic QA scenarios** behave as expected (12 English, 12 Roman Urdu, 12 Urdu), 8 basic API checks passed.
- The 36 cases are illustrative regression messages and are **NOT** real-world evaluation, a genuine fraud dataset or proof of model accuracy.
- Found two specific false negatives and fixed them:
  1. “Pay to avoid arrest” did not trigger the FIA-government threat rule because a broad negation detector treated “avoid” as advice. The threat detector now requires explicit anti-scam advice to suppress the flag.
  2. A job/visa approval requesting a processing fee via a consumer wallet was previously missed. A narrow wallet+advance-fee+job/visa rule now raises a warning. An ordinary careers-portal message does not trigger it.
- Fixed changes are isolated to `phishguard/pakistan_rules.py`; frontend design and deployed AI weight files unchanged.

## Reproduction

From `PHISHGUARD_GITHUB_READY/`:

```sh
python -m pytest -q
python scripts/step46_e2e_suite.py
python scripts/step46_submission_audit.py --run-tests
```

The latter commands create `reports/step46/` with synthetic QA result details, a JSON release-readiness report and a Markdown status against each of the 10 supervisor requirements. Do not interpret synthetic QA pass rate as real-world detection accuracy.

## University checklist

All 10 requirements from the supplied *PhishGuard: Developer Requirements* PDF are individually audited by the script. **There are genuine unresolved blockers**:

1. Verified, consented multilingual 3-class source dataset with adequate Urdu fraud examples.
2. **50–100 NEW real-world messages**, independently reviewed with retained source/consent proof, fully separate from development data.
3. URL supervised model validation on new verified malicious and normal links without the earlier serious false-positive problem.
4. Explainability claim: offline SHAP demonstrably tested, but live opt-in endpoint is local deletion sensitivity (not SHAP or LIME). LIME implementation was not smoke-tested due missing optional package.
5. Final research/viva results and formal evidence record.

## Deployment scope

Upload only the Step46 **patch** (`docs/`, `evaluation/`, `phishguard/`, `scripts/`, `tests/`) into the existing GitHub `PHISHGUARD_GITHUB_READY` folder. The private research archive, sender data, user messages, consent records, and trained experimental XLM-R weights are **not** in the patch.

Commit triggers Vercel only if that existing GitHub deployment is still connected. Confirm the deployment is Ready separately. This patch changes the backend Pakistani-context rules and adds offline tests and reports, not the website UI.

## Security note

This is offline message and URL **screening**, no verified sender authentication and no outbound URL scanning. An official-looking display name, SMS code, or hostname cannot prove the message is genuine. `Safe` means no strong indicator found by the demo, not guaranteed safe. Percentage is an uncalibrated risk indicator, not probability of fraud.
