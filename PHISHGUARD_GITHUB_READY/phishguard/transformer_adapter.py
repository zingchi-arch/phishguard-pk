"""Optional GPU-trained XLM-RoBERTa inference adapter.

The saved model is loaded only when PHISHGUARD_TEXT_BACKEND=xlmr and
models/xlmr_development contains a completed fine-tuned checkpoint.
"""
from pathlib import Path
import numpy as np

class TransformerPredictor:
    def __init__(self, folder):
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        path=Path(folder)
        if not (path/'config.json').exists():
            raise RuntimeError('Fine-tuned XLM-R checkpoint missing. Run scripts/train_transformer.py first.')
        self.torch=torch
        self.tokenizer=AutoTokenizer.from_pretrained(str(path),local_files_only=True)
        self.model=AutoModelForSequenceClassification.from_pretrained(str(path),local_files_only=True)
        self.model.eval()
        self.classes_=np.array(['Safe','Suspicious','Scam'])
    def predict_proba(self,messages):
        tok=self.tokenizer(list(messages),return_tensors='pt',padding=True,truncation=True,max_length=160)
        with self.torch.inference_mode():
            return self.torch.softmax(self.model(**tok).logits,dim=-1).cpu().numpy()
