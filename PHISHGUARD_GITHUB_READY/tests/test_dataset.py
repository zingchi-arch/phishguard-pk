from pathlib import Path
import pandas as pd
import pytest
ROOT=Path(__file__).resolve().parents[1]

def test_development_corpus_has_three_languages():
    if not (ROOT/'data/development_dataset.csv').exists():
        pytest.skip('Private/unlicensed research data excluded from public repository')
    d=pd.read_csv(ROOT/'data/development_dataset.csv')
    assert {'English','Roman Urdu','Urdu'}.issubset(set(d.language))
    assert set(d.label)=={'Safe','Suspicious','Scam'}
    assert (d.training_approved=='NO').all()

def test_split_template_disjoint():
    if not (ROOT/'data/dev_splits_WEAK_LABELS.csv').exists():
        pytest.skip('Private/unlicensed research split excluded from public repository')
    d=pd.read_csv(ROOT/'data/dev_splits_WEAK_LABELS.csv')
    s={name:set(d[d.split==name].template_group) for name in ['train','validation','test']}
    assert s['train'].isdisjoint(s['validation'])
    assert s['test'].isdisjoint(s['validation'])
    assert s['train'].isdisjoint(s['test'])
