"""Generate a conservative, evidence-aware status sheet against the ten FYP requirements.

This is a reproducibility/packaging audit, NOT model certification.  In
particular it never treats synthetic QA results or research source labels
as independently human verified real-world accuracy.
"""
from __future__ import annotations
import argparse, csv, json, subprocess, sys
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
REQUIREMENTS=[
  (1,'3,000-5,000 independently reviewed multilingual 3-class messages','BLOCKED','Source candidates exist; labels, consent/source rights and genuine Urdu scam examples not independently validated.'),
  (2,'NLP preprocessing (normalization, tokenization, TF-IDF)','IMPLEMENTED_PROVISIONAL','Source modules and software tests present; linguistic efficacy needs independent annotation.'),
  (3,'Naive Bayes, SVM, Random Forest, XLM-R, 70/15/15 metrics','RESEARCH_ONLY','NB/SVM/RF source-label trials and XLM-R research run exist; all-three-language representative independently labelled evaluation pending.'),
  (4,'URL supervised classifier, optional WHOIS, URL risk indicator','PARTIAL','Offline URL structural screening tested. Historical RF has high benign false alarms; not approved for production.'),
  (5,'Combined text and URL risk score and 3-level verdict','IMPLEMENTED_PROVISIONAL','/analyze returns an uncalibrated 0-100 indicator and Safe/Suspicious/Scam verdict.'),
  (6,'SHAP or LIME attribution and user reasons','PARTIAL','Actual offline SHAP experiment and rule explanations; public explanation API is deletion sensitivity, NOT SHAP/LIME.'),
  (7,'FastAPI REST API with error handling','IMPLEMENTED_TESTED','/analyze, /analyze/batch, /analyze/explain, input checks, /health; public rate controls not independently audited.'),
  (8,'Web user input and colored explanations','IMPLEMENTED_DEMO','User supplied live website screenshot; API and local frontend tests available; production smoke test requires deployment confirmation.'),
  (9,'50-100 independent real-message tests and error analysis','BLOCKED','No complete independently reviewed and leakage-free 50-100-message holdout; scripts only implement gate.'),
  (10,'Code, README, GitHub, diagrams, final defense report','PARTIAL','Project documentation and diagrams exist; final evidence-validated report and supervisor sign-off are pending.'),
]


def audit(project_root=ROOT, run_tests=False):
    root=Path(project_root)
    evidence={
        'source_code':(root/'phishguard'/'inference.py').is_file(),
        'rest_api':(root/'phishguard'/'api.py').is_file(),
        'nlp_preprocessing':(root/'phishguard'/'preprocessing.py').is_file(),
        'website_html':(root/'phishguard'/'web'/'index.html').is_file(),
        'baseline_nb':(root/'models'/'text_naive_bayes.joblib').is_file(),
        'baseline_svm':(root/'models'/'text_linear_svm.joblib').is_file(),
        'baseline_rf':(root/'models'/'text_random_forest.joblib').is_file(),
        'safe_url_policy':(root/'phishguard'/'url_policy.py').is_file(),
        'real_url_deploy_model':(root/'models'/'url_model_real.joblib').is_file(),
        'offline_shap_script':(root/'scripts'/'step45_shap_lime_explain.py').is_file(),
        'real_holdout_template':(root/'docs'/'STEP45_EXTERNAL_50_100_TEMPLATE.csv').is_file(),
        'external_evaluation_gate':(root/'scripts'/'step45_independent_test_gate.py').is_file(),
        'has_final_independent_50_100_evidence':False,  # deliberately cannot be certified by filesystem inspection
        'independent_three_class_training_provenance_verified':False,
        'comprehensive_real_urdu_fraud_tested':False,
    }
    qa_file=root/'reports'/'step46'/'step46_synthetic_QA_report.json'
    qa=json.loads(qa_file.read_text(encoding='utf-8')) if qa_file.exists() else None
    testing=None
    if run_tests:
        completed=subprocess.run([sys.executable,'-m','pytest','-q','--disable-warnings'],
            cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120)
        testing={'exit_code':completed.returncode,'last_lines':completed.stdout.strip().splitlines()[-3:]}
    return {'date_utc':datetime.now(timezone.utc).isoformat(),
        'project':'PhishGuard-PK', 'audit_type':'release_readiness_not_model_accuracy',
        'requirements':[{'pdf_requirement':i,'description':t,'status':st,'limitations':why} for i,t,st,why in REQUIREMENTS],
        'file_checks':evidence,
        'synthetic_qa':qa,
        'unit_test_run':testing,
        'final_university_acceptance_ready':False,
        'blocking_gaps':['authentic 3-class multilingual label provenance and permission',
            'independent real Urdu Fraud examples and adequate evaluation',
            '50-100 independent unseen genuine SMS review/evaluation',
            'real-world URL model validation with acceptable benign false alarms',
            'final report with evidence-based charts and supervisor sign-off'],
        'disclaimer':'This audit cannot authenticate sources, reviewer identity, deployment or real-world model performance.'}


def generate_markdown(report):
    lines=['# PhishGuard-PK | Step 46 University Submission Readiness',
       '', '**Research status, not a validated fraud detector.**',
       '', '| Req. | What the supervisor asked for | Status |',
       '|---|---|---|']
    for r in report['requirements']:
        lines.append(f"| {r['pdf_requirement']} | {r['description']} | **{r['status']}** |")
    lines.extend(['','## Confirmed technical QA (NOT real-message evaluation)', ''])
    qa=report['synthetic_qa']
    if qa:
        lines.append(f"- Hand-authored regression tests: {qa['qa_pass']}/{qa['total']} met expected safety behavior (not real-world accuracy).")
        lines.append('- 8 API checks: '+str(sum(qa['api_checks'].values()))+'/8 passed.')
    else:
        lines.append('- Step 46 regression test has not been executed in this checkout.')
    if report['unit_test_run']:
        lines.append('- Pytest outcome: '+str(report['unit_test_run']['last_lines']))
    lines.extend(['','## Five genuine blockers',''])
    lines.extend(f"{i}. {x}." for i,x in enumerate(report['blocking_gaps'],1))
    lines.extend(['','## What is safe to demonstrate now','',
       '- Public website/REST API and structural URL/PK context risk indicators.',
       '- Reproducible classical and XLM-R research comparisons with limitations disclosed.',
       '- SHAP research example and live opt-in deletion-sensitivity explanation (different methods).',
       '- BISP/Jeeto/OTP/challan/job-fraud synthetic QA and backend regression tests.',
       '', '## Restrictions', '',
       '- Never put original personal messages or consent records on public GitHub.',
       '- Do not label synthetic samples independently verified.',
       '- Do not claim a high source-label benchmark score equals deployment accuracy.',
       '- Do not present "Safe" as a verified genuine sender or a URL inspection.',
       '', 'Generated by `python scripts/step46_submission_audit.py --run-tests`.'])
    return '\n'.join(lines)+'\n'


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run-tests',action='store_true')
    parser.add_argument('--output',type=Path,default=ROOT/'reports'/'step46')
    a=parser.parse_args()
    a.output.mkdir(parents=True,exist_ok=True)
    r=audit(run_tests=a.run_tests)
    (a.output/'STEP46_RELEASE_READINESS.json').write_text(json.dumps(r,indent=2,ensure_ascii=False),encoding='utf-8')
    (a.output/'STEP46_SUBMISSION_STATUS.md').write_text(generate_markdown(r),encoding='utf-8')
    print(json.dumps({'requirements':len(r['requirements']),
        'status_counts':{v:sum(x['status']==v for x in r['requirements']) for v in {x['status'] for x in r['requirements']}},
        'synthetic_qa_pass':r['synthetic_qa']['qa_pass'] if r['synthetic_qa'] else None,
        'tests':r['unit_test_run'],
        'final_ready':False},indent=2))

if __name__=='__main__':
    main()
