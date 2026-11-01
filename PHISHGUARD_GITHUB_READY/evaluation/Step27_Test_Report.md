# PhishGuard-PK v1.1, Step 27: Synthetic regression evaluation

**Research status:** Development diagnostic only. NOT a verified field accuracy estimate.

- Messages checked: **90** (30 per language; 10 each Safe / Suspicious / Scam).
- Verdict agreements with manually assigned synthetic labels: **59/90**.
- Language detections matching intended script: **87/90**.
- Cases for manual error review: **33**.

## By language and intended label

| Language | Safe | Suspicious | Scam | Overall |
|---|---:|---:|---:|---:|
| English | 10/10 | 0/10 | 6/10 | 16/30 |
| Roman Urdu | 10/10 | 1/10 | 8/10 | 19/30 |
| Urdu | 10/10 | 6/10 | 8/10 | 24/30 |

## Confusion matrix (expected synthetic label x predicted label)

| Expected / Predicted | Safe | Suspicious | Scam |
|---|---:|---:|---:|
| Safe | 30 | 0 | 0 |
| Suspicious | 23 | 7 | 0 |
| Scam | 8 | 0 | 22 |

## Selected error examples

- **English Suspicious → Safe** (7.4/100): Hi, I found your profile online. Can you message me privately for a business opportunity?
- **English Suspicious → Safe** (27.9/100): You may be eligible for a prize. Please confirm with the organizers.
- **English Suspicious → Safe** (10.7/100): Your document needs attention. Check with your office administrator today.
- **English Suspicious → Safe** (3.0/100): A limited time shopping offer is waiting for you. Check the seller carefully.
- **English Suspicious → Safe** (21.1/100): Someone says they are from customer support and wants to contact you on WhatsApp.
- **English Suspicious → Safe** (16.2/100): An unknown sender says you have a delivery waiting but gives no tracking number.
- **English Suspicious → Safe** (36.2/100): Please review your recent account activity. This notice comes from an unknown number.
- **English Suspicious → Safe** (2.7/100): I have a part time job for you. Let us discuss the terms by private message.
- **English Suspicious → Safe** (17.3/100): You have been added to an investment updates group by a person you do not know.
- **English Suspicious → Safe** (23.8/100): An unfamiliar sender asks you to visit https://update-notice.example for account news.
- **English Scam → Safe** (21.8/100): Tax refund waiting! Give your CNIC and password to the agent immediately.
- **English Scam → Safe** (26.4/100): Pay a registration fee first to unlock your promised online job salary.
- **English Scam → Safe** (17.4/100): I am your manager. Buy gift cards and send the codes secretly right now.
- **English Scam → Safe** (13.0/100): Guaranteed huge return: send your deposit to this stranger before midnight.
- **Roman Urdu Safe → Safe** (12.9/100): Kal subah 9 baje class shuru hogi, apni copy sath lana.
- **Roman Urdu Safe → Safe** (8.9/100): Assalam o alaikum, aj sham meeting 6 baje hai.

## Important research limits

- Message examples here were authored for edge-case testing. They are not copied from actual Pakistani user inboxes and must not be counted as independently held-out real data.
- `Safe / Suspicious / Scam` decisions are subjective for ambiguous messages, particularly the Suspicious category.
- We checked for exact matches in the existing development dataset; different phrasings can still resemble existing training templates.
- Overall percentages from this synthetic diagnostic must not be presented as real-world performance or calibrated fraud probability.
- Actual next academic milestone: collect and independently label 50 to 100 authentic, redacted, previously unseen messages from all three languages; then freeze the test set, run and discuss per-class F1 and errors.
- URL domain-age checking requires trustworthy external data; offline fallback remains unvalidated.
