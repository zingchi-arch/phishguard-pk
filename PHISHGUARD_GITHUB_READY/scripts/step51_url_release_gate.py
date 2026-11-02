"""Conservative URL model promotion gate. Research metrics cannot authorize deployment.

Usage: python scripts/step51_url_release_gate.py --results evaluation/STEP50_EXTERNAL_RESEARCH_RESULTS.json
This tool NEVER requests, resolves, or visits candidate URLs.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path


def evaluate_release(results: dict) -> dict:
    e=results.get('external_source_diagnostics') or {}
    p=e.get('openphish_provider_label') or {}
    b=e.get('tranco_homepage_proxy') or {}
    reasons=[]
    if results.get('deployment_approved') is not False:
        reasons.append('The input must explicitly declare deployment_approved=false until independent review.')
    if (p.get('n') or 0) < 100:
        reasons.append('Fewer than 100 publisher-labelled phishing URLs in external sample.')
    if (b.get('n') or 0) < 200:
        reasons.append('Fewer than 200 popular-domain proxy URLs in external sample.')
    if b.get('n') and b.get('warnings_n') is not None:
        proxy_warning_rate=b['warnings_n']/b['n']
        if proxy_warning_rate > .05:
            reasons.append(f'Proxy benign warnings {proxy_warning_rate:.1%} exceed 5% diagnostic bound.')
    else:
        proxy_warning_rate=None
        reasons.append('Missing popular-domain proxy warning data.')
    if p.get('n') and p.get('warnings_n') is not None:
        source_phish_warning_rate=p['warnings_n']/p['n']
        if source_phish_warning_rate < .80:
            reasons.append(f'Provider-label phishing warning rate {source_phish_warning_rate:.1%} below 80% diagnostic bound.')
    else:
        source_phish_warning_rate=None
        reasons.append('Missing publisher phishing warning data.')
    if results.get('legacy_30_reference_urls_warning_count',99)>1:
        reasons.append('Reference legitimate URLs yield more than one warning out of 30.')
    # Core scientific safeguard: provider-labelled and popularity proxies alone
    # do not constitute independently adjudicated benign and phishing test data.
    reasons.append('NO independently adjudicated, leakage-free real-world external URLs with calibrated operating threshold.')
    return {
        'research_gate':'FAIL', 'production_approved':False,
        'provider_phish_warning_rate':source_phish_warning_rate,
        'tranco_homepage_proxy_warning_rate':proxy_warning_rate,
        'uci_holdout_accuracy':(results.get('uci_heldout_source_label_metrics') or {}).get('accuracy'),
        'blockers':reasons,
        'limitations':['Tranco popularity is not legitimacy certification',
                       'OpenPhish provider labels are not independent manual review',
                       'Historical UCI test accuracy is not current external accuracy',
                       'Model scores are not calibrated probabilities',
                       'No user-submitted URL is opened by this script']
    }


def main() -> None:
    ap=argparse.ArgumentParser()
    ap.add_argument('--results',type=Path,default=Path(__file__).resolve().parents[1]/'evaluation'/'STEP50_EXTERNAL_RESEARCH_RESULTS.json')
    ap.add_argument('--out',type=Path)
    args=ap.parse_args()
    report=evaluate_release(json.loads(args.results.read_text(encoding='utf-8')))
    output=json.dumps(report,ensure_ascii=False,indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(output+'\n',encoding='utf-8')
    print(output)
    # Exit non-zero so a CI system cannot accidentally promote a failed model.
    raise SystemExit(2)

if __name__=='__main__':
    main()
