# 12-slide final-year-project presentation outline

1. **Title:** PhishGuard-PK - Trilingual Scam & Phishing Message Detection
2. **Motivation:** Scam links and code-mixed Pakistani SMS, WhatsApp, social media, email
3. **Problem:** Plain keyword filtering misses Roman Urdu variations and local fraud patterns
4. **Objectives:** 3 languages, tri-class risk, suspicious URL scoring, explainability, usable UI
5. **Dataset & audit:** 8,155 candidate records from prior sources, 7,353 deduplicated, 5,750 development labels; NO approved real 3-class ground truth
6. **Preprocessing:** Urdu Unicode, Roman variants, URL placeholders, TF-IDF character n-grams
7. **Model experiments:** Naive Bayes / Linear SVM / Random Forest, grouped train/validation/test
8. **Results:** Include model-comparison chart and confusion matrix; emphasize weak-label status and poor Suspicious performance
9. **URL engine:** length, HTTPS, shorteners, keywords, optional WHOIS, synthetic-trained URL RF
10. **Explainability and architecture:** SHAP outputs plus user-facing reasons, FastAPI POST /analyze, Gradio
11. **Live demo:** English normal message, Roman Urdu OTP request, Urdu prize scam, suspicious URL
12. **Limitations & next experiments:** independent review, new Urdu examples, XLM-R training, 50-100 real tests, ethical considerations

**Presentation rule:** Do not claim 97% verified accuracy or 100% URL detection in the viva. The current dataset is provisional and includes synthetic examples.
