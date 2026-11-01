# Data sources and provenance (verify terms before republication)

| Source | Role | Label issue |
|---|---|---|
| UCI SMS Spam Collection | English ham/spam candidates | `spam` is not automatically Scam; only ham used as provisional Safe |
| Zenodo Roman Urdu phishing dataset | Roman Urdu candidate messages | Source `0/1` mapping is provisional and may contain templates |
| Pak Spam Guard GitHub | Urdu-script ham/spam candidates | `spam` not equivalent to phishing; Urdu spam excluded from 3-class training |
| Pakistan 2026 research SMS dataset | Normal/promotional/fraud candidate messages | Fraud and normal source labels unreviewed; promotional excluded |
| Synthetic Pakistani scenarios | Format coverage in three languages | Explicitly NOT authentic user messages; cannot substantiate real-world results |

See `data/candidate_inventory.csv` (source_url) and `data/synthetic_examples.csv` (source_url). License, redistribution, consent and origin must be individually checked before project publication or model commercialization.

References cited in original project user brief: UCI SMS Spam Collection, PhishTank, other public datasets. The delivered build does **not** claim to incorporate a verified PhishTank label file.

| UCI PhiUSIIL Phishing URL (2024, CC BY 4.0) | Real URL training notebook (not executed in delivered build) | Original label 1 = legitimate, 0 = phishing; convert carefully; cite original authors Prasad and Chandra |
