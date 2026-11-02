import json
from pathlib import Path
from scripts.step51_url_release_gate import evaluate_release

ROOT=Path(__file__).resolve().parents[1]

def sample():
    return json.loads((ROOT/'evaluation'/'STEP50_EXTERNAL_RESEARCH_RESULTS.json').read_text(encoding='utf-8'))

def test_reference_data_never_approved():
    r=evaluate_release(sample())
    assert r['production_approved'] is False
    assert r['research_gate']=='FAIL'

def test_warns_every_popular_domain():
    r=evaluate_release(sample())
    assert r['tranco_homepage_proxy_warning_rate']==1.0
    assert any('100.0%' in x for x in r['blockers'])

def test_external_phishing_rate_disclosed():
    r=evaluate_release(sample())
    assert r['provider_phish_warning_rate']==1.0
    assert r['uci_holdout_accuracy']==0.9961

def test_even_perfect_proxy_cannot_autocertify():
    d=sample()
    d['external_source_diagnostics']['tranco_homepage_proxy']['warnings_n']=0
    d['legacy_30_reference_urls_warning_count']=0
    r=evaluate_release(d)
    assert not r['production_approved']
    assert any('independently adjudicated' in x for x in r['blockers'])

def test_missing_data_fails_conservatively():
    r=evaluate_release({})
    assert not r['production_approved']
    assert len(r['blockers'])>=4
