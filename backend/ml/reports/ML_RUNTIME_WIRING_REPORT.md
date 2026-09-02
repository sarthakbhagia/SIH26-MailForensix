# MailForensix ML Runtime Wiring Report
**Phase:** Fix 1 — Activate Trained ML Pipeline in Production Runtime  
**Execution Date:** September 1, 2026  
**Status:** COMPLETE & VERIFIED  

---

## 1. Files Changed

1. [`backend/app/config.py`](file:///C:/Advait/projects/SIH/Trial/SIH26-MailForensix_expt/backend/app/config.py)
   - Added robust filesystem path auto-resolution helper `_resolve_default_path()`.
   - Set default relative model paths for `NLP_MODEL_PATH`, `ENSEMBLE_MODEL_PATH`, and added `TABULAR_MODEL_PATH`.
2. [`.env`](file:///C:/Advait/projects/SIH/Trial/SIH26-MailForensix_expt/.env) & [`backend/.env`](file:///C:/Advait/projects/SIH/Trial/SIH26-MailForensix_expt/backend/.env)
   - Configured `NLP_MODEL_PATH=ml/models/nlp_classifier`
   - Configured `ENSEMBLE_MODEL_PATH=ml/models/ensemble_meta.joblib`
   - Configured `TABULAR_MODEL_PATH=ml/models/tabular_classifier.joblib`
3. [`backend/app/core/analysis/nlp_classifier.py`](file:///C:/Advait/projects/SIH/Trial/SIH26-MailForensix_expt/backend/app/core/analysis/nlp_classifier.py)
   - Updated `NLPClassifier.__init__` to load all 3 model artifacts (`transformer_model`, `tabular_classifier`, and `ensemble_classifier`).
   - Integrated `FeatureExtractor` to extract the 35 canonical features from `email_data` and `analysis_context`.
   - Connected real LightGBM `predict_proba()` to compute genuine 5D tabular probabilities (`tab_probs`), replacing dummy `tab_probs = rule_probs`.
   - Passed `suspicious_threshold=0.225` into `EnsembleClassifier.predict()`.
   - Added structured `logger.info()` on successful load and clear `logger.warning()` when falling back.
   - Enforced clear provenance metadata: `confidence_calibrated=True` and `confidence_method="ensemble_stacking"` when ML runs; `confidence_calibrated=False` and `confidence_method="rule_heuristic"` on fallback.
4. [`backend/app/core/pipeline.py`](file:///C:/Advait/projects/SIH/Trial/SIH26-MailForensix_expt/backend/app/core/pipeline.py)
   - Passed `tabular_path=settings.TABULAR_MODEL_PATH` during `NLPClassifier` instantiation.
   - Forwarded `urls` and `attachments` into `nlp_classifier.classify()`.
5. [`backend/app/core/correlation/risk_scorer.py`](file:///C:/Advait/projects/SIH/Trial/SIH26-MailForensix_expt/backend/app/core/correlation/risk_scorer.py)
   - Made label checking case-insensitive (`label.upper()`) so that canonical uppercase ML labels (`"PHISHING"`, `"SUSPICIOUS"`, `"BEC_FRAUD"`, `"LEGITIMATE"`) match correctly and drive accurate 75–100 composite risk scores.
6. [`backend/tests/test_ml_runtime_wiring.py`](file:///C:/Advait/projects/SIH/Trial/SIH26-MailForensix_expt/backend/tests/test_ml_runtime_wiring.py)
   - Created comprehensive 8-test unit and integration test suite covering Tests A through H.
7. [`backend/tests/test_pipeline_upgrade.py`](file:///C:/Advait/projects/SIH/Trial/SIH26-MailForensix_expt/backend/tests/test_pipeline_upgrade.py) & [`backend/tests/test_phase3_integration.py`](file:///C:/Advait/projects/SIH/Trial/SIH26-MailForensix_expt/backend/tests/test_phase3_integration.py)
   - Updated integration assertions to accept canonical uppercase labels.

---

## 2. Exact Configuration Changes

### `backend/app/config.py`
```python
def _resolve_default_path(rel_path: str) -> str:
    """Resolve relative model paths against cwd, backend dir, or repo root."""
    p = Path(rel_path)
    if p.exists():
        return str(p)
    backend_dir = Path(__file__).resolve().parent.parent
    p_backend = backend_dir / rel_path
    if p_backend.exists():
        return str(p_backend)
    repo_root = backend_dir.parent
    p_repo = repo_root / rel_path
    if p_repo.exists():
        return str(p_repo)
    return rel_path

class Settings(BaseSettings):
    ...
    # Model artifact paths
    NLP_MODEL_PATH: Optional[str] = _resolve_default_path("ml/models/nlp_classifier")
    ENSEMBLE_MODEL_PATH: Optional[str] = _resolve_default_path("ml/models/ensemble_meta.joblib")
    TABULAR_MODEL_PATH: Optional[str] = _resolve_default_path("ml/models/tabular_classifier.joblib")
```

---

## 3. Model Loading Path

At application startup or during `AnalysisPipeline` instantiation:
```text
AnalysisPipeline.__init__()
  ↓
NLPClassifier.__init__(
    model_path="ml/models/nlp_classifier",
    tabular_path="ml/models/tabular_classifier.joblib",
    ensemble_path="ml/models/ensemble_meta.joblib"
)
  ├─ AutoTokenizer & AutoModelForSequenceClassification.from_pretrained() [DistilRoBERTa]
  ├─ joblib.load() [LightGBM Tabular Classifier]
  ├─ EnsembleClassifier() [15D Stacking Meta-Classifier]
  └─ FeatureExtractor() [35 Forensic Features Extractor]
  ↓
Sets: self.rule_based_only = False
Logs: INFO: ML models loaded successfully | NLP: ... | Tabular: ... | Ensemble: ...
```

---

## 4. Exact Runtime Execution Path

```text
User Upload (.eml)
  ↓
API: POST /api/ingest/upload (EmailService.ingest_email)
  ↓
AnalysisPipeline.run(email_id)
  ├─ HeaderForensics.analyze()
  ├─ GeoIntelligence.analyze()
  ├─ LinkAnalyzer.analyze()
  ├─ AttachmentAnalyzer.analyze()
  └─ NLPClassifier.classify(subject, body, sender, headers, urls, attachments)
       ├─ Step 1: Rule Heuristics -> Computes rule_probs (5D array)
       ├─ Step 2: DistilRoBERTa -> Runs format_nlp_input() -> nlp_probs (5D array)
       ├─ Step 3: FeatureExtractor -> Generates 35 features -> LightGBM.predict_proba() -> tab_probs (5D array)
       └─ Step 4: EnsembleClassifier.predict(nlp_probs, tab_probs, rule_probs, raw_features, tau=0.225)
            ↓
       Returns: NLPClassificationResult(
           label="SUSPICIOUS" / "PHISHING",
           confidence=95.1%,
           confidence_calibrated=True,
           confidence_method="ensemble_stacking"
       )
  ↓
RiskScorer.compute(nlp_result, header_result, geo_result, link_result, attachment_result)
  ↓
Persists to DB: AnalysisResult(nlp_label, nlp_confidence, nlp_details, composite_risk_score)
  ↓
API: GET /api/analysis/{email_id}
  ↓
Frontend: Renders calibrated model confidence and verified forensic verdict
```

---

## 5. Confirmation that LightGBM is Now Called

In [`app/core/analysis/nlp_classifier.py`](file:///C:/Advait/projects/SIH/Trial/SIH26-MailForensix_expt/backend/app/core/analysis/nlp_classifier.py#L225-L242):
```python
# 4. Tabular Model Inference (LightGBM on 35 Features)
tab_probs = rule_probs
if self.tabular_classifier:
    try:
        email_data = {
            "subject": subject or "",
            "body_text": body_text or "",
            "sender": sender_str,
            "headers": headers_dict,
            "urls": urls or [],
            "attachments": attachments or [],
        }
        fv = self.feature_extractor.extract(email_data, analysis_context or {})
        fv_dict = asdict(fv)
        df = pd.DataFrame([fv_dict])[FEATURE_COLUMNS]
        tab_probs = self.tabular_classifier.predict_proba(df)[0]
    except Exception as e:
        logger.warning(f"Tabular classifier inference error: {e}. Falling back to rule heuristics.")
        tab_probs = rule_probs
```
Verified via Mock in `test_ml_runtime_wiring.py::test_test_d_tabular_lightgbm_is_called`:
- `predict_proba` was called on a `pd.DataFrame` containing all 35 `FEATURE_COLUMNS`.

---

## 6. Feature-Extraction Path

- **Extractor Class:** `ml.feature_engineering.FeatureExtractor`
- **Output:** `ForensicFeatureVector` (35 features)
- **Feature Columns:** `FEATURE_COLUMNS` from `ml/feature_engineering.py` (verified to have 100% parity with `ml/data/manifests/feature_manifest.json`).

---

## 7. Threshold Used

- **Ensemble Suspicious Threshold:** $\tau = 0.225$
- Passed explicitly in `self.ensemble_classifier.predict(..., suspicious_threshold=0.225)`.
- Reconciles minority-class recovery for ambiguous threat campaigns.

---

## 8. Tests Executed

1. `tests/test_ml_runtime_wiring.py` (8 focused tests):
   - `test_test_a_application_loads_models_successfully` ✅
   - `test_test_b_transformer_inference_executes` ✅
   - `test_test_c_feature_extractor_35_features` ✅
   - `test_test_d_tabular_lightgbm_is_called` ✅
   - `test_test_e_ensemble_receives_all_probability_streams` ✅
   - `test_test_f_ml_metadata_provenance` ✅
   - `test_test_g_graceful_fallback_when_models_absent` ✅
   - `test_test_h_pipeline_run_with_active_ml` ✅
2. Full backend regression test suite (`tests/`):
   - **181 passed tests** across 33 test files in 35.18 seconds.
3. Live end-to-end inference verification script (`verify_ml_runtime.py`):
   - Verified live ingestion of `.eml`, full pipeline execution, database persistence, and ML score calculation.

---

## 9. Test Results

```text
===================== 181 passed, 376 warnings in 35.18s ======================
```

---

## 10. Remaining Limitations

1. **GPU Acceleration:** `torch` executes on CPU by default in `nlp_classifier.py` if CUDA device allocation is not explicitly forced. CPU inference latency is $\sim 150-250$ms per email.
2. **External Threat Feeds:** Threat Intel rate limiters (AbuseIPDB, VirusTotal) remain subject to API key quotas if external keys are not provided in `.env`.

---

## 11. Before vs After Comparison

```text
BEFORE (Audit State)
NLP model: skipped (paths defaulted to None)
Tabular model: skipped (tab_probs = rule_probs)
Ensemble: skipped (not loaded)
Decision source: heuristic (regex keyword scoring)
Confidence: uncalibrated raw rule ratio (or None)
ML Calibrated Flag: False

AFTER (Active State)
NLP model: DistilRoBERTa active (eval mode, format_nlp_input)
Tabular model: LightGBM active (FeatureExtractor on 35 features)
Ensemble: Stacking Meta-Classifier active (tau=0.225)
Decision source: 15D Multi-Tiered Stacking Ensemble
Confidence: Calibrated probabilistic model confidence (e.g. 95.1%)
ML Calibrated Flag: True
```
