"""OPTIONAL SHAP explanations for a message and URL. Run locally when shap is installed.
Usage: python scripts/run_shap.py 'You won a prize verify now https://bit.ly/claim'
Slow on CPU. This is actual SHAP for model prediction, distinct from rule-based explanations.
"""
import sys
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from phishguard.urls import extract_urls,feature_vector,FEATURE_NAMES

def explain_text(message):
    import shap
    model=joblib.load(ROOT/'models/text_model.joblib')
    classes=list(model.classes_)
    def predict(texts):
        return model.predict_proba(list(texts))
    masker=shap.maskers.Text(r'\W+')
    explainer=shap.Explainer(predict,masker,output_names=classes,algorithm='partition')
    shap_values=explainer([message],max_evals=50)
    pred=classes[int(np.argmax(model.predict_proba([message])[0]))]
    which=classes.index(pred)
    token_list=shap_values.data[0]
    value_list=shap_values.values[0,:,which]
    df=pd.DataFrame({'token':list(map(str,token_list)),'shap_contribution_to_'+pred:value_list})
    df['absolute_importance']=df.iloc[:,1].abs()
    df=df.sort_values('absolute_importance',ascending=False)
    df.to_csv(ROOT/'reports/shap_text_tokens.csv',index=False)
    print('Actual SHAP text tokens saved for predicted class:',pred)
    print(df.head(10).to_string(index=False))

def explain_url(message):
    import shap
    url_model=joblib.load(ROOT/'models/url_model_demo.joblib')
    urls=extract_urls(message)
    if not urls:return print('No URL present, skipping URL SHAP')
    X=np.array([feature_vector(urls[0])],dtype=float)
    explainer=shap.TreeExplainer(url_model)
    out=explainer.shap_values(X)
    if isinstance(out,list):risk_values=np.array(out[1])[0]
    elif np.asarray(out).ndim==3:risk_values=np.asarray(out)[0,:,1]
    else:risk_values=np.asarray(out)[0]
    df=pd.DataFrame({'feature':FEATURE_NAMES,'value':X[0],
            'shap_contribution_to_synthetic_url_risk':risk_values})
    df['absolute_importance']=df.shap_contribution_to_synthetic_url_risk.abs()
    df=df.sort_values('absolute_importance',ascending=False)
    df.to_csv(ROOT/'reports/shap_url_features.csv',index=False)
    print('Actual SHAP URL feature contributions saved (synthetic URL model).')
    print(df.head(10).to_string(index=False))

if __name__=='__main__':
    msg=' '.join(sys.argv[1:]) or 'You won a prize, verify at https://bit.ly/claim'
    try:
        explain_text(msg)
        explain_url(msg)
    except ImportError:
        print('Install optional dependency: pip install shap')
        raise
