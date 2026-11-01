# Viva preparation | short answers

**Q1. What is PhishGuard-PK?**
An educational multilingual scam-message risk screening prototype. It accepts English, Roman Urdu, Urdu and embedded links.

**Q2. What problem does it solve?**
Pakistanis receive deceptive SMS, WhatsApp and social-media messages, often code-mixed; generic filters may miss local transliterations and scam context.

**Q3. What is NLP?**
Natural Language Processing: methods to turn text into features suitable for machine learning.

**Q4. Why normalize Roman Urdu?**
One word appears as `kia`, `kiya` or `kya`; normalization reduces inconsistent spelling.

**Q5. What is TF-IDF?**
A feature representation that upweights character patterns common in one message but rarer across messages.

**Q6. Why character n-grams?**
They tolerate spelling differences between Urdu transliterations better than whole-word features alone.

**Q7. Which baseline models were trained?**
Complement Naive Bayes, calibrated Linear SVM, Random Forest. Compared on validation macro F1.

**Q8. Which baseline was selected?**
Random Forest won validation macro F1 in this particular unverified data build. This does not guarantee it wins on real data.

**Q9. What is XLM-RoBERTa?**
A multilingual transformer pretrained on many languages. Training code is supplied, but it has not been executed or validated in this bundle.

**Q10. Why group the split?**
The same template with a changed amount or OTP should not appear in both train and test. Group split reduces that leakage.

**Q11. Why 70/15/15?**
Training fits models, validation selects a model, and test gives a held-out estimate. Template groups cause slight deviations in exact row counts.

**Q12. Accuracy vs recall?**
Accuracy is total correct fraction. Scam recall is the share of scams detected. High accuracy may hide failures on rare Suspicious/Urdu messages.

**Q13. Why macro F1?**
It weights performance across classes equally, helping expose poor minority-class performance.

**Q14. What is a confusion matrix?**
A table of actual labels versus model predictions for Safe/Suspicious/Scam.

**Q15. How do URLs get scored?**
Offline features: URL length, special characters, HTTPS, shortening, unusual subdomains, suspicious keywords, and optional WHOIS age.

**Q16. Does HTTPS guarantee safety?**
No, malicious pages can also have HTTPS certificates.

**Q17. Why never open URLs automatically?**
To avoid visiting phishing pages and sending user data to attackers.

**Q18. What is WHOIS?**
Public registration metadata about domains. Domain age is missing by default and only optionally retrieved, without opening phishing sites.

**Q19. What is SHAP?**
A model explanation method estimating a feature's contribution to one prediction. This package generated sample SHAP word and URL feature reports.

**Q20. What is POST /analyze?**
A FastAPI endpoint that takes JSON with a message and returns verdict, indicative score, reasons and URL details.

**Q21. Why separate URL and text scores?**
A plausible message with a deceptive link may have a higher risk, and a text-only phishing message can be flagged without a URL.

**Q22. Is the score a fraud probability?**
No. Source labels are provisional and synthetic fixtures are present. It is only a research risk indicator.

**Q23. What are your major limitations?**
Sparse genuinely verified Urdu messages, weak Suspicious performance, sources not individually verified, synthetic URL model, no independent real-world test.

**Q24. Why not mark promotional spam as Scam?**
Unsolicited marketing is not automatically phishing. Doing so would corrupt ground truth.

**Q25. What remains for a defensible final thesis?**
Acquire independently labeled multilingual data, 50-100 genuinely new real cases, review source license, GPU transformer experiment, calibrated URL risk, and publish original GitHub repo.
