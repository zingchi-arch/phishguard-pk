# Step 27: Automated testing

Boss, ye 90 synthetic regression tests hain. Matlab ye examples humne development ke liye khud likhe. Ye asli Pakistani SMS ka verified test set nahi hain.

## Kaise run karna hai?
Project ZIP extract karne ke baad Python environment mein:

`python evaluation/RUN_90_SYNTHETIC_TESTS.py`

Is se `evaluation/REPRODUCED_RESULTS.csv` generate hogi.

## Kaun si problem mili?
* Safe: 30/30 correct
* Suspicious: 7/30 correct
* Scam: 22/30 correct
* English: 16/30, Roman Urdu: 19/30, Urdu: 24/30, based on synthetic labels.

WARNING: Ye scores actual field accuracy ya fraud probabilities nahi. Final FYP mein 50-100 genuinely new, redacted, independently verified real messages test karne honge. Synthetic examples ki phrasing training material se mil sakti hai.
