# PhishGuard-PK v2 status | 1 November 2026

## End-to-end implemented and tested
- Responsive FastAPI website, local install; no message history storage.
- Single message screening, English/Roman Urdu/Urdu.
- Batch CSV checking with up to 100 messages and result downloads.
- FastAPI JSON single/batch endpoints, health + model status + OpenAPI.
- Text normalization + trained classical models + provisional development metrics.
- URL extraction, feature checks (offline, no URL browsing), combined risk logic.
- Readable warning terms and SHAP analysis script.
- Gradio interface that can launch in Colab; tests pass locally.

## Present but must run on outside compute/data
- GPU fine-tuning XLM-RoBERTa using verified multilingual samples. Only code is provided, not saved weights.
- Real URL Random Forest training with independent labeled URLs. Only script provided, no verified real model.
- Genuine 50-100 new externally reviewed messages and error report. Script is ready; data is missing.

## Human/institutional requirements
- Student/advisor verification of source licenses, message labels and Urdu translations.
- Create remote GitHub repository in own account.
- Advisor approval, named authorship, originality statement, required university formatting.

The application is usable for educational screening and viva demonstration. It is NOT validated for serious fraud decisions.
