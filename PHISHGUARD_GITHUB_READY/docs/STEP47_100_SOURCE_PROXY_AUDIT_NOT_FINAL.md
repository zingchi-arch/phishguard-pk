# Step 47: 100-Record Source-Label Proxy (not final evaluation)

**This is not a human-verified real-world accuracy study.** All inputs are from the Step41 source-designated test partition with original weak source categories. The actual training corpus is not completely available for leakage proof.

| Item | Result |
|---|---:|
| Source-labelled candidates screened | 100 |
| Strict Normal/Fraud agreement (Suspicious is neither) | 98.0% |
| Source Fraud records triggering warning (Scam OR Suspicious) | 100.0% |
| Source Normal records triggering warning | 1.7% |
| Source Normal records incorrectly called Scam | 0.0% |

| Source language group | N | Fraud source N | Fraud warning recall proxy | Normal warning rate proxy |
|---|---:|---:|---:|---:|
| English/Latin (PK corpus estimate) | 54 | 24 | 1.0 | 0.0 |
| Roman Urdu | 43 | 18 | 1.0 | 0.0 |
| Urdu script | 3 | 0 | None | 0.3333 |

**Critical gap:** Urdu script has only 3 `ham` examples in the source test partition, and **zero source-labelled Urdu Fraud** examples. Roman Urdu `0/1` labels use an unverified provisional mapping. English/Latin group has not been individually language-verified.

The analyzer was run without fetching URLs. Its `Safe` verdict does **not** authenticate a sender. This benchmark is for diagnosis only.

## Final independent evaluation status

**BLOCKED:** 50-100 authentic, independently reviewed and permissioned messages across Safe/Suspicious/Scam, English/Roman Urdu/Urdu, with model-development overlap excluded. Missing real-world inputs cannot be fabricated or replaced with teacher-generated synthetic messages.
