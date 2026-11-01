# PhishGuard-PK v1.1: False-positive error analysis

## Failure observed during user test
- Input: Hi Ahmed, our meeting is scheduled for tomorrow at 10 AM. Please bring your documents. Thank you!
- Desired label: Safe (a benign scheduling message)
- Previous output: Suspicious, 37.6/100.
- Original text model class scores: Safe 61.5, Suspicious 1.7, Scam 36.8 (uncalibrated development model scores).
- Cause: A hard-coded Suspicious threshold of 35 was applied to a composite risk signal even though the model favored Safe and no strong abuse patterns were detected.

## What changed
- Suspicious cutoff raised from 35 to 45; Scam cutoff unchanged at 65.
- Provisional validation threshold comparison (weak labels) selected 45 to reduce ordinary-message false alerts.
- Added regression tests covering the reported meeting and English/Roman Urdu/Urdu examples.

## Limitations / remaining research
- Decision thresholds have not been calibrated on independently verified new messages.
- Higher cutoff can increase missed suspicious messages (false negatives). Do not treat lower scores as proof of safety.
- Urdu and Suspicious test labels are weak and sometimes synthetic. Final FYP needs an independent three-language labeled test set and error analysis.
- Other text and URL modules unchanged.
