# PhishGuard-PK | GitHub/Render Deployment

**Main entrypoint:** FastAPI app `phishguard.api:app` serves the public browser interface at `/`, and analyzer at `/analyze`. This repository contains deployable PROVISIONAL software, **not a fully validated security product**.

**Free deployment:** `render.yaml` and `requirements-deploy.txt` enable a free Render Web Service; Python 3.13.5 pinned to match trained artifact environment. See [`GITHUB_AND_RENDER_STEPS_ROMAN_URDU.md`](GITHUB_AND_RENDER_STEPS_ROMAN_URDU.md).

**Dataset privacy:** raw scraped/collected user messages and weak-label working sets are deliberately excluded from the public GitHub package. Trained provisional model artifacts are included for live inference, but cannot substitute for independent evaluation.

---

# PhishGuard-PK v2.0 | Full Software Build

A locally usable multilingual (English, Roman Urdu, Urdu) text and URL screening web application, with a REST API, Gradio/Colab interface, batch CSV checker, ML comparison and academic reporting framework.

**Honest scope:** The software works end-to-end, but research evaluation is NOT complete. Some text labels are weak / synthetic. The fine-tuned XLM-R checkpoint is NOT included. The default URL scoring remains offline heuristic, since the supplied RF demo was trained on synthetic URLs. Risk indicator is not a calibrated fraud probability. A result labeled Safe is NOT a safety guarantee.

## Launch methods

### A. Easy Google Colab (recommended for you)
1. Download `PHISHGUARD_V2_COLAB.ipynb` and `PHISHGUARD_V2_FULL_SOFTWARE.zip`.
2. Open https://colab.research.google.com → File → Upload notebook.
3. Runtime → Run all. Upload the ZIP when prompted.
4. Open the `gradio.live` link; leave the last notebook cell running. It supports both single and batch CSV messages. These links are temporary; **never paste private real messages into a public share link**.

### B. Full browser application, local installation
Use Python 3.11 or 3.12 on a modern OS/browser:

```bash
pip install -r requirements.txt
python run_web.py
```

Open **http://127.0.0.1:8000**. This is the new clean, responsive browser interface, including single-message checking, multi-message CSV screening, exportable JSON/CSV results and model status.

The JSON API documentation is at http://127.0.0.1:8000/docs.

### C. Alternative Gradio interface

```bash
python run.py
```

Opens at http://127.0.0.1:7860.

## API

- `GET /` → responsive website
- `GET /health` → health
- `GET /model-status` → model and training status
- `POST /analyze` → `{ "message": "text..." }`
- `POST /analyze/batch` → `{ "messages": ["one", "two"] }`, maximum 100 messages
- `GET /docs` → interactive OpenAPI documentation

No pasted URL is opened, and neither the web app nor API stores input history in a database. Public proxies, cloud hosting providers, web server logs, or client devices may still retain data, so redact all sensitive information before using a shared link.

## Dataset, training and evaluation

- Provisional development CSV, source inventory, structured 70/15/15 development split and model comparisons are under `data/` and `reports/`.
- Three baseline text classifiers were actually trained, with test split metrics and plots. These scores are **not** external real-world performance.
- `colab/TRAIN_XLMR_ON_GPU.ipynb` provides a ready-to-run GPU training workflow. `scripts/train_transformer.py` can train XLM-RoBERTa on a GPU after running `pip install -r requirements-advanced.txt`. This training **has not yet been run**. Optionally set `PHISHGUARD_TEXT_BACKEND=xlmr` after training to use its saved checkpoint in the app.
- `colab/TRAIN_REAL_URL_MODEL.ipynb` uses the CC BY 4.0 UCI PhiUSIIL URL source (235,795 raw records), obtains a reproducible 50,000-row sample and trains a disjoint-host model in Colab. Its output has not been run/verified here. Alternatively, `scripts/train_real_urls.py --csv data/real_urls_labeled.csv` trains a Random Forest on genuinely labeled benign/phishing URLs with a disjoint-host 70/15/15 train/validation/test split. The input CSV must contain `url,label,source`. It is not included because no independently licensed data collection was completed. Until supplied and trained, URL checking is heuristic only.
- `scripts/evaluate_external.py --csv path/to/independently_reviewed.csv` evaluates 50–100+ NEW real messages with columns `message,label,language,reviewer,source`, rejecting exact development duplicates. Independent new review set **not yet collected**.
- `scripts/run_shap.py 'example'` makes actual per-token SHAP explanations and URL demo feature attribution, with appropriate caveats; heuristic warning patterns are what the live interface shows by default.
- `python -m pytest -q` runs unit, API and regression tests.

## Requirements traceability

| Original # | What software includes | Remaining scientific/institutional work |
|---|---|---|
| 1 | 3-language candidates, source tracking, CSV processing | Verify 3,000–5,000 independent tri-class annotations and balance real Urdu |
| 2 | Urdu/Roman normalization, tokenization, stopwords, TF-IDF | Linguistic benchmark |
| 3 | NB, SVM, RF trained, splits/metrics; XLM-R GPU script and adapter | Finish actual XLM-R fine-tuning on verified dataset |
| 4 | URL parsing/features, risk, RF training script | Get legal real labeled phishing and benign URL dataset and train/validate |
| 5 | Combined text + URL indicators | Calibrate on separate set |
| 6 | Rule explanations and SHAP script + saved samples | User-facing on-demand SHAP integration / reviewer quality |
| 7 | FastAPI and validation | Public deployment security review |
| 8 | Responsive web app + Gradio, CSV batch | Permanent hosting / access management |
| 9 | Provisional grouped test and synthetic regression | Independently labeled 50–100 real message external test |
| 10 | Docs, diagrams, tests, report, README | Publish to university-approved GitHub; report format and advisor approval |

## Ethical use / limitations

- No automatic claim that a message or person is fraudulent.
- No browsing of suspicious links.
- No OTPs, passwords or private phone numbers should be submitted.
- Risk indicator is an uncalibrated screening measure, **not** a statistical likelihood or guaranteed determination.
- Training artifacts contain synthetic examples; report them transparently in the FYP thesis.

Current build: Nov 1, 2026. Authors/attribution to be completed by student according to university policy.

**Public repository test status:** two research-dataset tests skip intentionally because private/rights-uncertain datasets are not published. Other tests run without raw collected messages.
