# PhishGuard-PK, Step 57: Real code + two contributed dataset audits

**State:** The website and working SMS/URL structural screener are maintained. A new URL-Phish supervised candidate was trained, **but not activated** because it over-warns on legitimate-style deep links. Never claim this is an independently validated product.

## Source A, uploaded URL-Phish: Feature-Engineered Dataset (2026)

- Version 2: Linh Dam Minh, Hung Tran Cong, *URL-Phish: A Feature-Engineered Dataset for Phishing Detection*, Mendeley Data (2026), DOI [10.17632/65z9twcx3r.2](https://doi.org/10.17632/65z9twcx3r.2), **CC BY 4.0**. Attribution required.
- Uploaded CSV: 116,600 URLs, 100,000 labelled benign (0), 16,600 labelled phishing (1). The public source describes PhishTank provider data and academic/government/popular-domain sources for benign URLs.
- This run removed 1,369 exact duplicates (0 contradictory labels) leaving **115,231** unique URLs. **80,752 train, 17,872 validation, 16,607 test**, split on *registrable domain* using libpsl. No domain group overlap.
- Research-only histogram gradient-boosting model uses **34 lexically derived URL features**, computed consistently from each raw URL, not someone else's preprocessed scores. Threshold 0.50 chosen only on source validation, not external tests.
- **Within-source domain-held-out results:** accuracy **96.93%**, phishing recall **83.93%**, phishing precision **88.93%**, benign warning rate **1.37%** (16,607 test URLs). These are provider-labelled/source-specific metrics, **not 2026 Pakistan field accuracy**.
- **Major external usability red flag:** 4 of 30 existing legitimate reference links warned; **34 of 48 constructed deep-path stress cases** warned (e.g. benign domain + `/account/settings`, `/help`, `/login`). Constructed deep paths are probes, **not verified currently live benign URLs**. **NOT DEPLOYABLE**. Do not enable model, tune on external test, or place weights at `models/url_model_real.joblib`.
- Reproducible local training: `python scripts/step57_train_urlphish.py --data-zip 'URL-Phish...zip' --output private_results/`. Requires local scikit-learn and `libpsl`, no URL requests. Research weights at `models/urlphish_2026_RESEARCH_ONLY.joblib`; *not referenced by inference.py*.

## Source B, user-uploaded phishing_dataset_1000.xlsx

- 1,000 records: 595 source `0` nonphishing, 405 `1` phishing, English/Roman Urdu (0 Urdu-script rows), 16 source categories, 1,000 distinct raw messages but only **909 distinct normalized messages**.
- Labels are binary source labels; no class `Suspicious`; provenance/consent/independent adjudication not supplied; the repetitive wording suggests templated examples.
- Existing **text classifier only** batch diagnostic (not full API verdict): among 595 source-normal rows, model predicted Safe for 595; among 405 source-phishing rows, predicted Scam for 357 and Suspicious for 48. May reflect source/template overlap and is **not valid external recall or accuracy**.
- One narrow production rule was improved based on identified redirection patterns: bank/wallet `account blocked` threat + urgent demand to reply to a **private 03xx mobile number**. Generic bank transaction alerts without a private mobile number are not included. This is a structural safety signal, not verified sender authentication.
- The raw XLSX / extracted messages are **NOT included in GitHub or release**, to avoid accidentally distributing possible personal phone numbers.

## Third-party repositories reviewed

1. [amruth112/fraudurl-detector](https://github.com/amruth112/fraudurl-detector): reported MIT-licensed offline URL fraud triage, 83 lexical/domain features, review/uncertainty class, explanation and model calibration; claims are developer-reported and not revalidated here. The upstream model/training data was **not imported or copied**. Repo model has its own source license/attribution obligations; an internet-restricted environment prevented cloning. Good architectural reference for later independent benchmark and measured acceptance criteria.
2. [munazat/UrduStack](https://github.com/munazat/UrduStack): MIT-licensed research on Pakistani code-switched scam/abuse and LoRA XLM-R. It uses **toxicity/hate-speech** datasets and **synthetic scam templates**. Toxic != phishing; those labels should never be silently merged into PhishGuard Scam/Suspicious/Safe. Repo weights/training data were **not imported or copied**, and we do not claim to have re-trained XLM-R with UrduStack. It suggests useful preprocessing/normalization ideas for separately reviewed future experiments.

## University requirements still open

1. **Real independent evaluation:** 50–100 new, previously unseen, independently labelled genuine SMS (English, Roman Urdu, **Urdu script**) with safe handling and source-rights evidence. None supplied here.
2. Urdu-script fraud positives, third-class Suspicious labels and comprehensive source-provenance verification.
3. Reliable supervised URL model with robust **legitimate deep-link** false-alarm validation and a fully independent temporal/provider holdout. Both previous UCI and this URL-Phish run failed practical external stress checks.
4. A final research claims audit and supervisor sign-off, followed by final dissertation/viva evidence.

**Scientific integrity:** A functioning website is not the same thing as proven fraud-detection accuracy. Current output never opens links or authenticates senders. Never market `Safe` as an authenticated real sender or website.
