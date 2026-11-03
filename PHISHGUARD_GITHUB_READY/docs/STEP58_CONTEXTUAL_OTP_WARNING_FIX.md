# Step 58 | Context-aware OTP/PIN warning fix

## Problem fixed
The original classical text classifier and keyword safety rules could mark warnings such as "Apna OTP kisi ko share na karna" as Scam, even though they expressly prohibit sharing the credential.

## Changes
- New `phishguard/message_intent.py`: local, deterministic English / Roman Urdu / Urdu-script clause and negation recognition, including mixed warning + actual request.
- `pakistan_rules.py`: avoid mistaking a negative request ("share na karna") for an affirmative bank credential request.
- `explain.py`: do not call a protective message a "Credential or verification request" or highlight harmless OTP/PIN words as warning words; independently detect dangerous payment / verification links.
- `inference.py`: when there is explicit protective advice, no dangerous link, no scam rule, and no actual credential request, cap the uncalibrated model indicator below the Suspicious threshold, and disclose the context guard in the API response. Does not authenticate the sender.
- `web/app.js`: make clear the raw text-model indicator is **pre-context**, and show credential sharing context separately.
- `tests/test_step58_security_advice_intent.py`: 27 hand-authored contrasting examples, **not** independent real-world accuracy data.

## Verified locally
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q`

Result: **186 passed, 2 skipped**. Two user-reported Roman Urdu messages now return Safe; affirmative OTP requests and the combined "do not share, but send it to us" cases remain high risk. This is not a claim of real-world reliability.

## Open-source multilingual ML option (not deployed)
**sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2** is Apache-2.0 and includes Urdu in its multilingual set. It produces sentence embeddings; it is **not** a trained Safe/Suspicious/Scam or scam-intent classifier by default. Roman Urdu spelling variation is not independently validated. Its model weights are about 471MB, before runtime packages. Current deployment should keep the light-weight classical model and the tested context guard. A neural model needs a *separate* fine-tuning/evaluation cycle, hard-negative contrastive examples, and deployable inference infrastructure. Avoid sending private messages to unapproved external inference APIs.

## Safety and limitations
- A Safe label does not verify the organization, sender or bank transaction.
- Messages asking for OTP/PIN, deceptive links, prize/fee requests and mixed safety+solicitation still need to be flagged. This is a bounded set of language patterns, not general language comprehension.
- The user's real-world independent 50-100-message blind evaluation remains outstanding.
