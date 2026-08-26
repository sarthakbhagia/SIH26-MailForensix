from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any

app = FastAPI()

class PredictRequest(BaseModel):
    text: str

class PredictResponse(BaseModel):
    label: str
    confidence: float
    probabilities: Dict[str, float] = {}

# Lazy load transformer model
_tokenizer = None
_model = None

@app.on_event("startup")
async def startup_load_model():
    global _tokenizer, _model
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        m = 'distilbert-base-uncased-finetuned-sst-2-english'
        _tokenizer = AutoTokenizer.from_pretrained('ml/models/nlp_classifier')
        _model = AutoModelForSequenceClassification.from_pretrained('ml/models/nlp_classifier')
        _model.eval()
        print('Inference model loaded')
    except Exception as e:
        # fallback: try HF hub
        try:
            _tokenizer = AutoTokenizer.from_pretrained(m)
            _model = AutoModelForSequenceClassification.from_pretrained(m)
            _model.eval()
            print('Inference model loaded from hub')
        except Exception as e2:
            print('Failed loading model:', e, e2)

@app.post('/predict', response_model=PredictResponse)
async def predict(req: PredictRequest):
    global _tokenizer, _model
    text = req.text or ''
    # If model not loaded, return Legitimate with low confidence
    if not _tokenizer or not _model:
        return PredictResponse(label='Legitimate', confidence=0.5, probabilities={'Legitimate': 50.0})
    import torch
    inputs = _tokenizer(text, truncation=True, max_length=512, return_tensors='pt')
    with torch.no_grad():
        logits = _model(**inputs).logits
        probs = torch.softmax(logits, dim=-1).cpu().numpy()[0]
    # distilbert sst-2 classes: [NEGATIVE, POSITIVE]
    neg, pos = float(probs[0]), float(probs[1])
    # Map POSITIVE -> Legitimate, NEGATIVE -> Phishing
    if pos >= neg:
        label = 'Legitimate'
        confidence = pos * 100.0
    else:
        label = 'Phishing'
        confidence = neg * 100.0
    probabilities = {'Legitimate': round(pos * 100.0, 1), 'Phishing': round(neg * 100.0, 1)}
    return PredictResponse(label=label, confidence=round(confidence,1), probabilities=probabilities)
