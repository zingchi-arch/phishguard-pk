# Step 64 - Friend impersonation and urgent wallet transfer risk

## Purpose
This update fixes a false negative for messages that claim to be a friend, demand a large urgent transfer and supply a private mobile wallet number. It uses multiple local risk signals and does not authenticate senders.

## Previously missed example
`ma noman bat krha hoo mujy arjunt 50000 jazzcash krdo is number pr 03409878555 mujhy bhot zroori kaam ha`

Previous local verdict: **Safe 44.9/100**. Updated local verdict: **Scam 93/100**, with `PK_FRIEND_IMPERSONATION_URGENT_TRANSFER`.

## Logic
- Detect a direct request to transfer money through a wallet or bank/payment channel.
- Evaluate urgency, explicit large value (10,000+ PKR, 50k, 50 hazar, pachas hazar, etc.), private 03xx contact, named-person introduction, and requests to pay an explicitly supplied number.
- Multiple cues trigger a stronger warning. One name, personal number or bank transaction receipt alone does not prove fraud.
- Less conclusive small transfers or nonurgent requests remain lower severity.
- An explicit awareness notice about this scam avoids the new payment request rule; other classifiers may still produce a warning.
- Avoid claims that a user's saved contacts, sender ownership or a recipient account were verified. No contacts permissions, bank account authentication or financial transactions occur.
- Do not click or fetch message URLs to establish legitimacy. Deep AI can provide a second opinion on redacted text only after opt-in; explicit high-risk local rules remain active if Deep AI disagrees.

## Privacy and responsible interpretation
A message claiming a friend's name is not authenticated. A legitimate acquaintance could also urgently request money, so 'Scam' here indicates a high-risk pattern, **not proven deception**. Risk scores are research indicators, not calibrated probabilities. Independently call a person on a trusted pre-existing number before transferring funds. No recipient private number is included in automated explanations.

## Verification
Local automated suite: **277 passed, 2 skipped** on the Step 63 codebase with the Step 64 changes. The tests cover the exact reported message; multiple Roman Urdu, English and Urdu phrasings; normal bank receipts; greeting; OTP protection; small-value transfers; API result; Deep AI conflict; privacy redaction; version identity.

Real user interaction and production deployment must be verified after GitHub commit / Vercel Ready. This is not a real-world accuracy study.
