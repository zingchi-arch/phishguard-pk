"""Synthetic URL-only feature demo. No real malicious URLs are visited.
User must supply independently labeled benign/phishing URLs for defensible evaluation.
"""
from pathlib import Path
import sys,json,random
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import classification_report,accuracy_score,f1_score
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from phishguard.urls import feature_vector,FEATURE_NAMES
random.seed(2401)

# Make a small non-operational fixture set. All fake phishing domains use reserved .invalid TLD.
SAFE=['https://www.example.com/help','https://www.sbp.org.pk/','https://www.fbr.gov.pk/',
      'https://www.pakistanpost.gov.pk/', 'https://github.com/about',
      'https://www.microsoft.com/security', 'https://google.com/accounts',
      'https://docs.python.org/3/library/']
FAKE=['http://account-review-bank.invalid/login','http://rewards-now.invalid/claim-prize',
      'http://bisp-payment-check.invalid/verify','http://delivery-confirm-update.invalid/parcel',
      'http://verify-wallet-otp.invalid/login','http://192.0.2.91/secure/login',
      'http://user@security-warning.invalid/update','https://login.verify.account.award.invalid/claim',
      'https://bit.ly/claim-bonus','https://tinyurl.com/verify-account-now']

def create_fixture():
    data=[]
    # Variation groups stay together to reduce same-template leakage.
    for idx,b in enumerate(SAFE):
        for j in range(30):
            url=b+('?ref='+str(j) if j%3==0 else ('?page='+str(j) if j%3==1 else ''))
            data.append({'url':url,'label':0,'scenario_group':'safe-'+str(idx),'origin':'synthetic_variation_not_real_corpus'})
    for idx,b in enumerate(FAKE):
        for j in range(30):
            url=b+('?uid='+str(j)+'&verify=1' if j%3==0 else ('?token='+str(j) if j%3==1 else ''))
            data.append({'url':url,'label':1,'scenario_group':'fake-'+str(idx),'origin':'synthetic_variation_not_real_corpus'})
    df=pd.DataFrame(data)
    df.to_csv(ROOT/'data/synthetic_url_fixtures_DO_NOT_USE_AS_REAL.csv',index=False)
    return df

def train():
    df=create_fixture()
    grp=GroupShuffleSplit(n_splits=1,test_size=.25,random_state=4)
    tr,te=next(grp.split(df,groups=df.scenario_group))
    train_df=df.iloc[tr];test_df=df.iloc[te]
    xtr=np.asarray([feature_vector(u) for u in train_df.url],dtype=float)
    xte=np.asarray([feature_vector(u) for u in test_df.url],dtype=float)
    model=RandomForestClassifier(n_estimators=120,max_depth=8,random_state=42,
                                class_weight='balanced',n_jobs=-1,min_samples_leaf=2)
    model.fit(xtr,train_df.label)
    pred=model.predict(xte)
    result={'n_train':len(train_df),'n_test':len(test_df),
     'accuracy':float(accuracy_score(test_df.label,pred)),
     'macro_f1':float(f1_score(test_df.label,pred,average='macro',zero_division=0)),
     'feature_importance':dict(zip(FEATURE_NAMES,[round(float(x),4) for x in model.feature_importances_])),
     'critical_note':'SYNTHETIC scenario-derived URLs only. These metrics are NOT real phishing-detection accuracy.',
     'domain_age':'Optional WHOIS only; unknown by default because external querying is disabled.'}
    joblib.dump(model,ROOT/'models/url_model_demo.joblib',compress=3)
    (ROOT/'reports/url_demo_metrics.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print('URL demo trained:',result['n_train'],result['n_test'],result['accuracy'])

if __name__=='__main__':train()
