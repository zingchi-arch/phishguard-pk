"""All scenarios here are authored QA fixtures, NOT real phishing measurements."""
from pathlib import Path
import csv
import io
import zipfile
import pytest
from phishguard.url_policy import assess_url
from scripts.step48_url_benchmark import load_public_candidates,assess_rows,confusion

@pytest.mark.parametrize('url',[
    'https://gov.pk.verify-8171.example.invalid/claim',
    'https://bisp-gov-pk.verify.example.invalid/claim',
    'https://www.gov.pk.phish.example.invalid',
    'https://hbl-com.verify.example.invalid/login',
])
def test_strong_offline_namespace_and_domain_spoofs(url):
    a=assess_url(url)
    assert a.indicator>=75 and a.high_confidence_structure, (url,a)

@pytest.mark.parametrize('url',[
    'https://www.sbp.org.pk/', 'https://bisp.gov.pk/',
    'https://fbr.gov.pk/', 'https://www.github.com/',
    'https://www.google.com/search?q=gov.pk.verify-8171',
    'https://github.com/python/cpython',
])
def test_government_markers_are_not_auto_safe_or_auto_phishing(url):
    a=assess_url(url)
    assert a.indicator<45, (url,a)


def test_counter_math_does_not_swap_phishing_labels():
    a=confusion([('phishing',True),('phishing',False),('legitimate',True),('legitimate',False)])
    assert a['confusion_rows_true_columns_predicted']==[[1,1],[1,1]]
    assert a['phishing_missed_FN']==1


def test_schema_rejects_label_reversal(tmp_path):
    f=tmp_path/'fixture.zip'
    with zipfile.ZipFile(f,'w') as z:
        data=io.StringIO()
        w=csv.DictWriter(data,fieldnames=['url','label_uci','label','source'])
        w.writeheader(); w.writerow({'url':'https://example.org','label_uci':'0','label':'legitimate',
                     'source':'UCI PhiUSIIL 2024'})
        z.writestr('URL_10000_STRATIFIED_CANDIDATES.csv',data.getvalue())
    with pytest.raises(ValueError,match='conflicting'):
        load_public_candidates(f)


def test_benchmark_flags_dataset_label_not_model_confidence():
    baseline,rows=assess_rows([{'url':'https://gov.pk.login.example.invalid','true':'phishing'},
                            {'url':'https://github.com/python/cpython','true':'legitimate'}])
    assert baseline['phishing_flagged_TP']==1
    assert baseline['legitimate_warned_FP']==0
    assert all(len(r['url_sha256'])==64 for r in rows)
    assert not any('url' in r for r in rows)
