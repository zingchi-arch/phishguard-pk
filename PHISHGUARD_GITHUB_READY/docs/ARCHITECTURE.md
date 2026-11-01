# PhishGuard-PK v2 architecture

```mermaid
flowchart TD
    A[English / Roman Urdu / Urdu input] --> B[FastAPI browser website or Gradio]
    C[CSV up to 100 messages] --> B
    B --> D[POST analyze or batch API]
    D --> E[Input validation]
    E --> F[Text language + normalization]
    E --> G[Extract URLs offline, without opening]
    F --> H[Classical TF-IDF model or optional fine-tuned XLM-R]
    G --> I[Lexical URL features and WHOIS optional]
    I --> J[Offline URL heuristic or future real labeled URL RF]
    H --> K[Combined risk and rule signals]
    J --> K
    K --> L[Safe / Suspicious / Scam + indicator]
    K --> M[Readable explanation and warning terms]
    L --> N[Website, JSON, optional CSV download]
    M --> N
```

## Evaluation architecture

```mermaid
flowchart TD
    A[Public sources and independently reviewed message data] --> B[Redact, deduplicate, keep provenance]
    B --> C[Label review / group by template]
    C --> D[70/15/15 split]
    D --> E[NB / SVM / Random Forest / XLM-R]
    E --> F[Validation selection]
    F --> G[Held-out test + per-language error analysis]
    H[50-100 new independent real messages] --> I[External evaluation]
    G --> J[Report and limitations]
    I --> J
```

No suspicious user URL is visited or executed during analysis. Optional WHOIS looks up domain registration metadata and is OFF by default.
