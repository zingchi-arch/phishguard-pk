# Step 59: context-sensitive OTP/PIN understanding

**Release**: `step59-intent-hybrid-v1` (API version 2.1.0)

## Why this patch exists

A live screenshot on 2026-11-03 showed a bank/wallet safety notice, "share na krna", misclassified as Scam with rule-floor 90. The same exact user sentence already returned **Safe** in the Step58 working code. This indicates the screenshot reflected a previous deployed version or an incomplete deployment. Step59 therefore adds a server release fingerprint shown on the website.

## Implementation

- **Already existing**: TF-IDF text classifier, safety context grammar, Pakistan scam-rule floors, conservative offline URL structural screening.
- **NEW**: independent local, free/open-source scikit-learn character-gram logistic-regression *intent* model. Four labels: `protect`, `request`, `mixed`, `other`. 1,480 generated/development examples, **not independent real SMS**. We do NOT claim a validated accuracy, a pretrained LLM, sender verification, or a calibrated confidence score.
- Explicit negation/context logic now understands `na`, `nhe`, `nah`, `nh`, `nai` and cross-clause attempts such as `OTP mat bhejna lekin humein send krdo`.
- Safety guard applies only without disqualifying payment/link/solicitation or strong risk rule. A Safe text verdict does not authenticate a financial message or sender.
- No model APIs, API keys, external calls, browser-side large downloads, or user-text logging.

## Rebuild and verification

From `PHISHGUARD_GITHUB_READY/`, run:

```
python scripts/train_intent_ai.py
python -m pytest -q
```

The release archive includes the pre-trained 122-KB `models/intent_ai_step59.joblib` so users do **not** need to train it again for normal deployment. Only load project-supplied artifact files, never untrusted pickle/joblib uploads.

### Production deployment proof

1. Open `https://phishguard-pk.vercel.app/health` after deployment.
2. Confirm `release_id` equals `step59-intent-hybrid-v1` and `intent_ai_available` is `true`.
3. Open the analyzer. Its status pill should say **Intent AI active · Step 59**.
4. Test `apka jazzcash accoutn bngya ha mubarak ho apna pin ya otp ksi kay sath share na krna`. It should return **Safe** and show **AI message intent: Safety advice**.
5. Compare `HBL apna PIN humein send karo warna account block ho jayega`, which should produce **Scam**.

If the pill says **Old backend detected · update pending**, the Vercel backend is still serving old code. Check the GitHub commit path and Vercel deployment, rather than assuming training didn't work.

## Research limitations

This is a tested **code regression fix**, NOT proof of general scam-detection accuracy. The intent model was trained on templated research examples. The existing source-labelled URL candidate still fails external false-positive constraints; it remains non-deployed. Urdu-script and Roman Urdu real-world independent test coverage must be improved before an academic accuracy claim. No secrets or external URLs are fetched by the inference engine.
