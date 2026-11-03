"""New source-regression tests. No synthetic/provisional source is claimed verified."""
import json
import csv
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from phishguard.api import app
from phishguard.inference import analyze_message
from phishguard.pakistan_rules import assess_pakistani_context
from phishguard.url_ml_research import features,FEATURES
from scripts.step57_train_urlphish import registered_domain

ROOT=Path(__file__).resolve().parents[1]
client=TestClient(app)


def test_uploaded_sms_source_is_explicitly_not_gold():
    s=json.loads((ROOT/'evaluation/STEP57_SMS1000_SOURCE_AUDIT.json').read_text())
    assert s['records']==1000
    assert s['label_0_count']==595 and s['label_1_count']==405
    assert s['urdu_script_records']==0
    assert s['third_class_Suspicious_in_source'] is False
    assert s['independent_human_verified'] is False
    assert s['no_raw_SMS_in_repository']


def test_new_url_model_not_silently_deployed():
    s=json.loads((ROOT/'evaluation/STEP57_URLPHISH_RESEARCH_RESULTS.json').read_text())
    assert s['rows']>100000
    assert s['model_deployment_approved'] is False
    assert s['registered_domain_group_overlap']==0
    status=client.get('/model-status').json()
    assert status['urlphish_2026_model_in_live_decision'] is False
    assert status['urlphish_2026_research_candidate'] is True
    diag=client.get('/research-status').json()['latest_uploaded_dataset_status']
    assert diag['urlphish_url_model_live'] is False
    assert diag['sms1000_urdu_script_records']==0


def test_fixed_offline_feature_vector_no_network():
    a=features('https://github.com/python/cpython/issues/123')
    b=features('https://github.com/python/cpython/issues/123')
    assert len(a)==len(FEATURES)==34
    assert (a==b).all()


def test_bank_block_redirect_private_mobile_flagged():
    m='Apka HBL account block ho gaya hai. Abhi call karein 03001234567 warna account band ho jayega.'
    assert any(p.rule_id=='PK_BANK_BLOCK_PRIVATE_MOBILE' for p in assess_pakistani_context(m))
    assert analyze_message(m)['verdict']=='Scam'


def test_normal_bank_helpline_mention_no_private_mobile_rule():
    m='Aap ka HBL debit card ATM par use hua hai. Agar aap ne nahi kiya to bank helpline par call karein.'
    assert not any(p.rule_id=='PK_BANK_BLOCK_PRIVATE_MOBILE' for p in assess_pakistani_context(m))


def test_url_authentication_warning_preserved():
    o=client.post('/analyze',json={'message':'https://github.com/example/project'}).json()
    assert o['url_verification_status']=='NOT_VERIFIED_OFFLINE_ONLY'
    assert o['urls'][0]['url_authenticity']=='NOT_VERIFIED'


def test_research_sources_not_external_accuracy():
    js=(ROOT/'phishguard/web/app.js').read_text()
    assert 'No independently verified Urdu-script holdout' in js
    assert 'urlphish_url_model_live' in (ROOT/'phishguard/api.py').read_text()
