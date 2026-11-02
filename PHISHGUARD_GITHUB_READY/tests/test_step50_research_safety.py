"""Step50 non-network tests only. These do NOT establish real-world accuracy."""
import csv
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from step50_supervised_external_research import host_of, registered_group, read_uci, _csv_hash_records

def test_parse_hostname_no_network():
    assert host_of('https://github.com/path')=='github.com'
    assert host_of('https://example.com.evil.invalid/login')=='example.com.evil.invalid'

def test_grouping_public_suffix_or_exact_host_conservative():
    assert registered_group('https://a.github.com/') == registered_group('https://b.github.com/') or registered_group('https://a.github.com/') == 'a.github.com'

def test_external_artifacts_are_hash_only():
    u='https://example.invalid/secret?x=test'
    x=_csv_hash_records([u],[0.7],'fake_test',0.5)[0]
    assert set(x)=={'url_sha256','hostname_sha256','cohort','model_score_not_calibrated','warning'}
    assert u not in str(x)
    assert x['warning'] is True

def test_uci_mapping_and_conflicting_label_quarantine(tmp_path):
    p=tmp_path/'urls.csv'
    with p.open('w',newline='',encoding='utf8') as f:
        w=csv.writer(f);w.writerow(['url','label_uci']);w.writerow(['https://safe.example','1']);w.writerow(['https://phish.example','0']);w.writerow(['https://safe.example','0'])
    d,audit=read_uci(p)
    assert len(d)==1
    assert int(d.iloc[0].label)==1
    assert audit['conflicting_url_values_removed']==1

def test_not_deploy_after_external_regression():
    p=Path('/mnt/data/STEP50_WORK/private/offline_historical_external_40_30/STEP50_RESULTS.json')
    if p.exists():
        report=json.loads(p.read_text())
        assert report['deployment_approved'] is False
        assert report['external_source_diagnostics']['tranco_homepage_proxy']['warnings_n'] >= 25
