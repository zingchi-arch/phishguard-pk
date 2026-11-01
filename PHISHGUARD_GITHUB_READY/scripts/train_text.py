"""Weak-label research demo training: grouped 70/15/15 split.
The reported scores MUST NOT be presented as validated fraud-detection performance.
"""
import json
import sys
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import ComplementNB
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report,confusion_matrix,accuracy_score,precision_recall_fscore_support,f1_score,ConfusionMatrixDisplay
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from phishguard.preprocessing import normalize_message

LABELS=['Safe','Suspicious','Scam']

def split_grouped(df):
    # Templates grouped so closely related SMS do not appear on both sides.
    gss=GroupShuffleSplit(n_splits=1,test_size=.15,random_state=42)
    train_val_idx,test_idx=next(gss.split(df,groups=df.template_group))
    rem=df.iloc[train_val_idx]; test=df.iloc[test_idx].copy()
    # 15% of total: .15/.85 = .17647 of remaining.
    gss2=GroupShuffleSplit(n_splits=1,test_size=.15/.85,random_state=43)
    tr_idx,va_idx=next(gss2.split(rem,groups=rem.template_group))
    train=rem.iloc[tr_idx].copy(); val=rem.iloc[va_idx].copy()
    train['split']='train';val['split']='validation';test['split']='test'
    assert not (set(train.template_group)&set(val.template_group))
    assert not (set(train.template_group)&set(test.template_group))
    assert not (set(test.template_group)&set(val.template_group))
    assert set(LABELS).issubset(set(train.label))
    return train,val,test

def pipeline(name):
    if name=='Naive Bayes':model=ComplementNB(alpha=.6)
    elif name=='Linear SVM':
        model=CalibratedClassifierCV(LinearSVC(class_weight='balanced',random_state=42),cv=3,method='sigmoid')
    elif name=='Random Forest':model=RandomForestClassifier(n_estimators=115,max_depth=30,
                          min_samples_leaf=2,max_features='sqrt',class_weight='balanced_subsample',random_state=42,n_jobs=-1)
    else:raise ValueError(name)
    return Pipeline([('tfidf',TfidfVectorizer(preprocessor=normalize_message,
        lowercase=False,analyzer='char',ngram_range=(3,5),sublinear_tf=True,
        min_df=2,max_features=18000)),('classifier',model)])

def score(model,rows):
    pred=model.predict(rows.message)
    accuracy=accuracy_score(rows.label,pred)
    p,r,f,_=precision_recall_fscore_support(rows.label,pred,average='macro',zero_division=0)
    return {'accuracy':round(float(accuracy),4),'precision_macro':round(float(p),4),
            'recall_macro':round(float(r),4),'f1_macro':round(float(f),4)}

def train():
    df=pd.read_csv(ROOT/'data/development_dataset.csv',dtype=str).fillna('')
    train,val,test=split_grouped(df)
    split=pd.concat([train,val,test],ignore_index=True)
    split.to_csv(ROOT/'data/dev_splits_WEAK_LABELS.csv',index=False,encoding='utf-8-sig')
    print('Split:',len(train),len(val),len(test))
    print('Classes:\n',pd.crosstab(split.split,split.label))
    print('Languages:\n',pd.crosstab(split.split,split.language))
    rows=[];trained={}
    for name in ['Naive Bayes','Linear SVM','Random Forest']:
        print('Training:',name,flush=True)
        est=pipeline(name)
        est.fit(train.message,train.label)
        v=score(est,val)
        rows.append({'model':name,'selection_split':'validation',**v})
        trained[name]=est
        filename={'Naive Bayes':'text_naive_bayes.joblib','Linear SVM':'text_linear_svm.joblib','Random Forest':'text_random_forest.joblib'}[name]
        joblib.dump(est,ROOT/'models'/filename,compress=3)
    val_table=pd.DataFrame(rows).sort_values('f1_macro',ascending=False)
    best_name=val_table.iloc[0]['model']
    # Evaluate ONLY after model selected by validation. No test tuning.
    test_rows=[]
    for name,est in trained.items():
        test_rows.append({'model':name,'split':'test_WEAK_LABELS',**score(est,test)})
    comparison=pd.DataFrame(test_rows)
    comparison.to_csv(ROOT/'reports/text_model_comparison.csv',index=False)
    val_table.to_csv(ROOT/'reports/validation_model_comparison.csv',index=False)
    best=trained[best_name]
    joblib.dump(best,ROOT/'models/text_model.joblib',compress=3)
    predicted=best.predict(test.message)
    cm=confusion_matrix(test.label,predicted,labels=LABELS)
    cm_df=pd.DataFrame(cm,index=LABELS,columns=LABELS)
    cm_df.to_csv(ROOT/'reports/text_confusion_matrix.csv')
    fig,ax=plt.subplots(figsize=(6,5))
    ConfusionMatrixDisplay(confusion_matrix=cm,display_labels=LABELS).plot(ax=ax,cmap='Blues',colorbar=False,values_format='d')
    ax.set_title(f'{best_name}: Provisional test labels only')
    fig.tight_layout();fig.savefig(ROOT/'reports/confusion_matrix.png',dpi=170);plt.close(fig)
    fig,ax=plt.subplots(figsize=(7,4))
    ax.bar(comparison.model,comparison.f1_macro)
    ax.set_ylim(0,1);ax.set_ylabel('Macro F1 vs provisional source labels')
    ax.set_title('Weak-label evaluation, NOT a verified real-world benchmark')
    ax.tick_params(axis='x',rotation=8)
    fig.tight_layout();fig.savefig(ROOT/'reports/model_comparison.png',dpi=170);plt.close(fig)
    by_lang={}
    for language,subset in test.groupby('language'):
        ypred=best.predict(subset.message)
        by_lang[language]={'n':len(subset),'accuracy':round(accuracy_score(subset.label,ypred),4),
                'f1_macro':round(f1_score(subset.label,ypred,average='macro',zero_division=0),4),
                'synthetic_n':int((subset.origin_type=='synthetic_illustration').sum()),
                'warning':'Non-independent source labels and synthetic scenarios; interpret cautiously.'}
    metrics={'best_by_validation':best_name,'split_counts':{x:len(y) for x,y in [('train',train),('validation',val),('test',test)]},
        'validation_results':rows,'test_results':test_rows,'by_language_weak_test':by_lang,
        'classification_report_provisional':classification_report(test.label,predicted,labels=LABELS,zero_division=0,output_dict=True),
        'synthetic_rows_in_corpus':int((df.origin_type=='synthetic_illustration').sum()),
        'sources_individually_reviewed':0,
        'critical_note':'NOT final performance: all public source labels provisional; some examples synthetic. No verified independent test.'}
    (ROOT/'reports/text_metrics.json').write_text(json.dumps(metrics,indent=2,ensure_ascii=False),encoding='utf-8')
    meta={'status':'Research demonstration, weak-label and synthetic training data',
      'language_support':['English','Roman Urdu','Urdu'], 'best_text_model':best_name,
      'model_input':'message text','trained_on_unapproved_labels':True,
      'calibrated_realworld_probability':False,'url_supervision':'Synthetic-only demo',
      'limitations':['Urdu-script samples mostly synthetic','Suspicious class mainly synthetic',
                     'Weak public labels, no independent annotation','Not production security advice']}
    (ROOT/'models/model_metadata.json').write_text(json.dumps(meta,indent=2,ensure_ascii=False),encoding='utf-8')
    print('Selected by validation:',best_name)
    print('Results on provisional test labels:')
    print(comparison.to_string(index=False))
    return best_name

if __name__=='__main__':train()
