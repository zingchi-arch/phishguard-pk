"""Unit tests on mock feeds only. Never request URLs or external hosts."""
from __future__ import annotations
import csv
import json
import sys
import zipfile
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import step49_external_url_evaluation as s


def test_fixed_external_sources_and_no_candidate_fetch(monkeypatch,tmp_path):
    calls=[]
    def fake_open(req,timeout=0):
        calls.append(req.full_url)
        assert req.full_url in s.SOURCES.values()
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return b'https://bisp.gov.pk.evil.invalid/claim\n'
        return Response()
    class DummyOpener:
        def open(self, req, timeout=0): return fake_open(req,timeout)
    monkeypatch.setattr(s.urllib.request,'build_opener',lambda *a:DummyOpener())
    assert s._download_only_publisher('openphish').startswith(b'https://')
    assert calls==[s.OPENPHISH_SOURCE]


def test_malformed_and_duplicate_phish_removed():
    feed=b'#comment\nhttps://example.invalid/a\nhttps://example.invalid/a\njavascript:alert(1)\nhttps://second.invalid/\n'
    assert len(s._parse_urls_from_openphish(feed))==2
    assert len(s._sample_phishing(s._parse_urls_from_openphish(feed),200))==2


def test_tranco_csv_and_zip_parse(tmp_path):
    content=b'1,example.com\n2,python.org\n3,example.com\n4,evil name.com\n'
    assert len(s._parse_tranco(content))==3  # duplicate rank rows remain, sampled unique
    archive=tmp_path/'t.zip'
    with zipfile.ZipFile(archive,'w') as z:z.writestr('top-1m.csv',content)
    assert s._parse_tranco(archive.read_bytes())==s._parse_tranco(content)
    assert len(s._sample_tranco(s._parse_tranco(content),10))==2


def test_offline_diagnostic_provenance_and_privacy(tmp_path):
    phishing=b'https://github.com.evil.invalid/login\nhttps://bisp.gov.pk.evil.invalid/claim\nhttps://random.invalid/\n'
    proxy=b'1,github.com\n2,wikipedia.org\n3,python.org\n'
    r=s.evaluate(phishing,proxy,tmp_path,'UNIT_TEST_FIXTURES',n=3)
    assert r['url_model_deployment_approved'] is False
    assert r['openphish']['selected_distinct_hosts']==3
    assert r['openphish']['warning_45_n']==2
    assert r['tranco']['warning_45_n']==0
    assert r['tranco']['selected_distinct_hosts']==3
    assert r['result_status']=='RESEARCH_DIAGNOSTIC_COMPLETE_NO_DEPLOYMENT'
    text=(tmp_path/'STEP49_HASHED_CASES_ONLY.csv').read_text('utf-8-sig')
    assert 'evil.invalid' not in text and 'github.com' not in text
    assert 'http' not in text
    assert len(list(csv.DictReader(text.splitlines())))==6


def test_missing_external_feed_not_faked(tmp_path):
    r=s.evaluate(None,b'1,github.com\n',tmp_path,'UNIT_TEST_FIXTURES',errors={'openphish':'network unavailable'})
    assert r['result_status']=='INCOMPLETE_SOURCE_FETCH'
    assert r['openphish']['status']=='NOT_AVAILABLE'
    assert r['openphish']['n']==0
    assert r['publisher_errors']['openphish']=='network unavailable'
