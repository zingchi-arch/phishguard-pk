# Data dictionary and label policy

## Files
- `candidate_inventory.csv`: 7,353 deduplicated source candidates from prior audits. Not all are suitable for three-class training.
- `synthetic_examples.csv`: 213 synthetic educational examples, three languages, scenario labels (not actual received messages).
- `development_dataset.csv`: 5,750 **weakly labeled or synthetic** messages used for the demo.
- `dev_splits_WEAK_LABELS.csv`: grouped training/validation/test split, stored for reproducibility.
- `synthetic_url_fixtures_DO_NOT_USE_AS_REAL.csv`: fictitious URL data used solely for a functional URL classifier demo.

## Main columns
- `message`: redacted text.
- `language`: supplied / heuristic label; `Unverified Latin` is deliberately NOT forced to English or Roman Urdu.
- `label`: tentative Safe, Suspicious, Scam for demo training only.
- `source`: dataset or scenario source.
- `source_label`: original label from public source.
- `origin_type`: source-candidate or synthetic.
- `template_group`: grouped IDs to prevent obvious same-template train/test overlap.
- `training_approved`: **NO** for all rows. Must not be quietly flipped to YES.

## Label guidance for human reviewers
- **Safe**: normal logistics/transactional text without manipulation or unsolicited sensitive requests.
- **Suspicious**: warning signs but insufficient proof of malicious intent (do not equate normal promotions with suspicious automatically).
- **Scam**: clear fraud/deception request, e.g. fake prize requiring PIN or OTP.
- **Unknown / discard**: missing context, unverifiable, too short, private, or conflicted labels.

## Verification protocol
1. Redact names, phone, account IDs, URLs with tracking tokens.
2. Two people label independently without seeing provisional label.
3. Record language, category, evidence/source, label rationale, reviewed date, reviewer.
4. Resolve disagreements, keep evidence in a separate, access-controlled file.
5. Lock 50-100 new independent real messages for a true external evaluation.
