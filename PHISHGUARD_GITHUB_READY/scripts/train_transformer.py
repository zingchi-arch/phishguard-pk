"""Optional GPU training for multilingual XLM-RoBERTa. Not run in this CPU build.
Run in Google Colab with GPU and requirements-advanced.txt installed.
Do not present model as evaluated until run completed on reviewed data.
"""
import json
from pathlib import Path
import numpy as np
import pandas as pd
import torch
from datasets import Dataset
from transformers import (AutoTokenizer,AutoModelForSequenceClassification,
    TrainingArguments,Trainer,DataCollatorWithPadding)
from sklearn.metrics import f1_score,accuracy_score,precision_recall_fscore_support
ROOT=Path(__file__).resolve().parents[1]
NAME='xlm-roberta-base'
LABELS=['Safe','Suspicious','Scam']


def main():
    if not torch.cuda.is_available():
        print('WARNING: no GPU. This model can take a long time on CPU. Colab GPU recommended.')
    table=pd.read_csv(ROOT/'data/dev_splits_WEAK_LABELS.csv').fillna('')
    tokenizer=AutoTokenizer.from_pretrained(NAME)
    def prepare(split):
        data=table[table.split==split][['message','label']].copy()
        data['labels']=data['label'].map({l:i for i,l in enumerate(LABELS)}).astype('int64')
        data=data.drop(columns='label')
        ds=Dataset.from_pandas(data,preserve_index=False)
        return ds.map(lambda d:tokenizer(d['message'],truncation=True,max_length=160),batched=True)
    train=prepare('train');val=prepare('validation');test=prepare('test')
    model=AutoModelForSequenceClassification.from_pretrained(NAME,num_labels=3,
      id2label={i:x for i,x in enumerate(LABELS)},label2id={x:i for i,x in enumerate(LABELS)})
    args=TrainingArguments(output_dir=str(ROOT/'models/xlmr_checkpoints'),
      learning_rate=2e-5,per_device_train_batch_size=8,per_device_eval_batch_size=8,
      num_train_epochs=2,weight_decay=.01,eval_strategy='epoch',save_strategy='epoch',
      load_best_model_at_end=True,metric_for_best_model='f1_macro',greater_is_better=True,
      save_total_limit=1,report_to='none',fp16=torch.cuda.is_available(),seed=42)
    def metrics(p):
        pred=np.argmax(p.predictions,axis=-1)
        precision,recall,f1,_=precision_recall_fscore_support(p.label_ids,pred,average='macro',zero_division=0)
        return {'accuracy':accuracy_score(p.label_ids,pred),'f1_macro':f1,
                'precision_macro':precision,'recall_macro':recall}
    trainer=Trainer(model=model,args=args,train_dataset=train,eval_dataset=val,
      processing_class=tokenizer,data_collator=DataCollatorWithPadding(tokenizer),
      compute_metrics=metrics)
    trainer.train()
    result=trainer.evaluate(test)
    target=ROOT/'models/xlmr_development'
    trainer.save_model(target);tokenizer.save_pretrained(target)
    (ROOT/'reports/xlmr_optional_metrics.json').write_text(json.dumps({'result':result,
      'caution':'Weak labels and synthetic examples. NOT a defensible final benchmark.'},indent=2),encoding='utf-8')
    print('Saved XLM-RoBERTa to',target)

if __name__=='__main__':main()
