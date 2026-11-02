"""Step49: SOURCE-CLAIMED phishing and popular-domain proxy checks.

Compares local URL structural warnings against two documented *different*
sources. NEVER opens candidate pages, resolves domains, or fetches redirect
chains. Network mode downloads ONLY two hard-coded publisher datasets, NOT
any URL contained in them. No model/threshold selection against these data.

This is independent-source *diagnostics*, NOT a validated phishing classifier.
The Tranco set is a popularity proxy, not a collection of authenticated
legitimate webpages. Phishing URLs can occur on trusted hostnames.

Offline usage:
 python scripts/step49_external_url_evaluation.py \\
  --phishing-file path/to/OpenPhish_feed.txt \\
  --proxy-file path/to/Tranco_list.csv --output /private/results

Download mode (safe publisher feeds only):
 python scripts/step49_external_url_evaluation.py --download --output /private/results
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import random
import sys
import urllib.request
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from phishguard.url_policy import assess_url

# Both values derived from public publishers; do not accept arbitrary fetch URLs.
OPENPHISH_SOURCE = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt'
TRANCO_ID = 'V354N'  # list created 2026-11-01 (see https://tranco-list.eu/list/V354N)
TRANCO_SOURCE = f'https://tranco-list.eu/download_daily/{TRANCO_ID}'
SOURCES = {'openphish': OPENPHISH_SOURCE, 'tranco': TRANCO_SOURCE}
ACCEPTED_TYPES = ('.txt', '.csv', '.zip')
MAX_BYTES = 38 * 1024 * 1024
N_LIMIT = 400


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _download_only_publisher(which: str) -> bytes:
    """Fixed URL only. NEVER follows a URL *from* either publisher feed."""
    url = SOURCES[which]
    req = urllib.request.Request(url, headers={
        'User-Agent': 'PhishGuard-PK-academic-offline-evaluation/1.0',
        'Accept': 'text/plain,text/csv,application/zip,application/octet-stream',
    })
    # Publisher URL fixed; Python may follow publisher HTTP redirects.
    # Never pass any malicious/test URL to urlopen.
    class SameHostOnlyRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            # Keep requests on the selected publisher host; never follow an
            # arbitrary malicious redirect when downloading threat feeds.
            newparts=urlsplit(newurl)
            if newparts.scheme!='https' or newparts.hostname!=urlsplit(url).hostname:
                raise ValueError('Publisher attempted a cross-host / non-HTTPS redirect')
            return super().redirect_request(req,fp,code,msg,headers,newurl)
    opener=urllib.request.build_opener(SameHostOnlyRedirect())
    with opener.open(req, timeout=35) as res:
        data = res.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('Publisher feed exceeds size cap')
    return data


def _parse_urls_from_openphish(raw: bytes) -> list[str]:
    contents = raw.decode('utf-8-sig', errors='replace')
    seen = set()
    out = []
    for line in contents.splitlines():
        u = line.strip()
        if not u or u.startswith('#') or u in seen or len(u) > 10000:
            continue
        if urlsplit(u).scheme.lower() not in ('http','https'):
            continue
        if not urlsplit(u).hostname:
            continue
        seen.add(u)
        out.append(u)
    return out


def _parse_tranco(raw: bytes) -> list[tuple[int, str]]:
    if raw[:4] == b'PK\x03\x04':
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            valid = [i for i in z.infolist() if i.filename.lower().endswith('.csv') and not i.is_dir()]
            if not valid or len(valid) != 1 or valid[0].file_size > MAX_BYTES * 4:
                raise ValueError('Invalid Tranco ZIP structure')
            with z.open(valid[0]) as f:
                content = f.read(MAX_BYTES * 4 + 1)
                if len(content) > MAX_BYTES * 4:
                    raise ValueError('Tranco uncompressed size cap')
    else:
        content = raw
    result = []
    for row in csv.reader(io.StringIO(content.decode('utf-8-sig', errors='replace'))):
        if len(row) < 2:
            continue
        try:
            rank = int(row[0].strip())
        except ValueError:
            continue
        domain = row[1].strip().lower().strip('.')
        if not domain or '/' in domain or ':' in domain or '@' in domain or ' ' in domain:
            continue
        try:
            domain.encode('idna')
        except UnicodeError:
            continue
        # Tranco entries are base domains; their homepage is only a *proxy*.
        result.append((rank,domain))
    return result


def _sample_phishing(urls: list[str], n: int) -> list[str]:
    # Uniform sample by hostname, one example per hostname; avoid 200 URLs
    # from the same compromised domain counting as 200 independent successes.
    by_host: dict[str,str] = {}
    for url in urls:
        hostname = (urlsplit(url).hostname or '').lower()
        if hostname not in by_host:
            by_host[hostname] = url
    hosts = sorted(by_host)
    random.Random(20261102).shuffle(hosts)
    return [by_host[h] for h in hosts[:n]]


def _sample_tranco(rows: list[tuple[int, str]], n: int) -> list[tuple[int,str]]:
    # Draw a reproducible subset of the *top 100k* domains. This is not a
    # verified non-phishing set and contains only base-domain homepages.
    seen = set()
    eligible=[]
    for rank,domain in rows:
        if rank > 100000 or domain in seen:
            continue
        seen.add(domain)
        eligible.append((rank,domain))
    eligible.sort()
    random.Random(4902).shuffle(eligible)
    return eligible[:n]


def _score_cases(urls: list[str], kind: str, rank_map: dict[str,int]|None=None):
    out = []
    for url in urls:
        result=assess_url(url)
        # Do not include real malicious URLs, full domains, paths, screenshots,
        # query strings, passwords, or token values in any result artifacts.
        host = (urlsplit(url).hostname or '').lower()
        row={'record_hash':_sha(url), 'host_hash':_sha(host), 'cohort':kind,
             'score':result.indicator, 'status':result.status,
             'warning_45':result.indicator>=45, 'warning_75':result.indicator>=75,
             'rank':(rank_map or {}).get(host,''),
             'signals':len(result.reasons)}
        out.append(row)
    return out


def _metrics(rows:list[dict], positive:bool):
    n=len(rows)
    return {'n':n, 'warning_45_n':sum(x['warning_45'] for x in rows),
            'warning_75_n':sum(x['warning_75'] for x in rows),
            'warning_45_rate':round(sum(x['warning_45'] for x in rows)/n,4) if n else None,
            'warning_75_rate':round(sum(x['warning_75'] for x in rows)/n,4) if n else None,
            'interpretation':('phishing feed catch rate, NOT verified universal recall' if positive
                 else 'warning frequency on popular-domain homepages, NOT false-positive rate on authenticated safe sites')}


def evaluate(openphish_raw:bytes|None, tranco_raw:bytes|None, output:Path,
             source_mode:str, n:int=N_LIMIT, errors:dict[str,str]|None=None) -> dict:
    output.mkdir(parents=True,exist_ok=True)
    report={'experiment':'STEP49_FRESH_SOURCE_URL_DIAGNOSTIC_NOT_FINAL_MODEL_EVALUATION',
            'timestamp_utc':datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'mode':source_mode, 'tranco_list_id':TRANCO_ID,
            'sources':SOURCES, 'fixed_thresholds_not_tuned_on_test':[45,75],
            'record_selection':'deterministic host-diverse OpenPhish sample, deterministic top-100k Tranco domain homepage sample',
            'any_candidate_URL_opened':False,
            'safety':'No candidate URL requests, DNS resolution or content fetch. Only publishers fetched when --download set.',
            'source_and_label_limits':[
              'OpenPhish is provider-labelled feed, not a separately human-authenticated Pakistani phishing dataset.',
              'Tranco rank is not proof of domain safety, and homepage proxies underrepresent legitimate deep paths.',
              'Matching host names between two sources need investigation; do not infer ground truth from either alone.',
              'This is not a random representative sample of 2026 Pakistani SMS phishing or current web traffic.',
              'Not a calibration study, no confidence intervals or F1/accuracy claims, no trained model deployment allowed.'
            ],
            'url_model_deployment_approved':False,
            'independent_50_100_real_SMS_evaluation_done':False,
            'publisher_errors':errors or {}}
    rows=[]
    host_sets={}
    for name, raw in [('openphish',openphish_raw),('tranco',tranco_raw)]:
        if raw is None:
            report[name]={'status':'NOT_AVAILABLE','n':0}
            continue
        report[f'{name}_publisher_bytes_sha256']=hashlib.sha256(raw).hexdigest()
        if name=='openphish':
            candidates=_parse_urls_from_openphish(raw)
            chosen=_sample_phishing(candidates,n)
            curr=_score_cases(chosen,'OpenPhish_feed_label')
            host_sets[name]={urlsplit(x).hostname.lower() for x in chosen}
            report[name]={'status':'SOURCE_LABELLED_NOT_INDEPENDENTLY_REVIEWED','raw_valid_unique_urls':len(candidates),
                          'selected_distinct_hosts':len(chosen),**_metrics(curr,positive=True)}
        else:
            candidates=_parse_tranco(raw)
            chosen=_sample_tranco(candidates,n)
            rank_map={d:i for i,d in chosen}
            curr=_score_cases(['https://'+domain+'/' for i,domain in chosen],'Tranco_top100k_homepage_proxy',rank_map)
            host_sets[name]={d for _,d in chosen}
            report[name]={'status':'POPULAR_DOMAIN_PROXY_NOT_VERIFIED_BENIGN','raw_parsed_domains':len(candidates),
                          'selected_distinct_hosts':len(chosen),**_metrics(curr,positive=False)}
        rows+=curr
    if len(host_sets)==2:
        report['selected_hostname_overlap_n']=len(host_sets['openphish'] & host_sets['tranco'])
    if rows:
        path=output/'STEP49_HASHED_CASES_ONLY.csv'
        with path.open('w',newline='',encoding='utf-8-sig') as f:
            w=csv.DictWriter(f,fieldnames=list(rows[0]))
            w.writeheader();w.writerows(rows)
    report['result_status']='INCOMPLETE_SOURCE_FETCH' if len(host_sets)<2 else 'RESEARCH_DIAGNOSTIC_COMPLETE_NO_DEPLOYMENT'
    (output/'STEP49_SOURCE_DIAGNOSTIC.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    return report


def main(args=None):
    p=argparse.ArgumentParser()
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--download', action='store_true',help='download only two fixed publisher feeds')
    g.add_argument('--phishing-file',type=Path,help='downloaded public OpenPhish feed locally')
    p.add_argument('--proxy-file',type=Path,help='local Tranco CSV or ZIP; required with --phishing-file')
    p.add_argument('--output',type=Path,default=Path.cwd()/'step49_private_output')
    p.add_argument('--n',type=int,default=N_LIMIT)
    a=p.parse_args(args)
    if not 1<=a.n<=2000:
        p.error('--n must be 1..2000')
    if a.phishing_file and not a.proxy_file:
        p.error('--proxy-file required with --phishing-file')
    raw={};errors={}
    if a.download:
        for which in SOURCES:
            try:
                raw[which]=_download_only_publisher(which)
            except Exception as exc:
                errors[which]=f'{type(exc).__name__}: {str(exc)[:200]}'
                raw[which]=None
    else:
        raw={'openphish':a.phishing_file.read_bytes(),'tranco':a.proxy_file.read_bytes()}
    report=evaluate(raw['openphish'],raw['tranco'],a.output,
                    'LIVE_PUBLISHER_FEEDS' if a.download else 'SUPPLIED_PUBLISHER_FILES',a.n,errors)
    print(json.dumps({key:report[key] for key in ['result_status','openphish','tranco','publisher_errors','url_model_deployment_approved']},indent=2))
    return report

if __name__=='__main__':
    main()
