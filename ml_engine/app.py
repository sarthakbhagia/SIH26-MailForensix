from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional

from email_parser import parse_eml, extract_originating_ip, detect_cloud_webmail, extract_timezone_info
from heuristics import check_header_anomalies, check_url_anomalies
from nlp_model import evaluate_email_nlp
from risk_aggregator import calculate_total_risk
from geo_service import resolve_ip_geolocation

app = FastAPI(
    title="MailForensix ML Threat Detection Engine",
    description="Fast, modular email forensic threat analysis & risk scoring engine",
    version="1.3.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class JsonAnalysisRequest(BaseModel):
    from_header: Optional[str] = ""
    return_path: Optional[str] = ""
    subject: Optional[str] = ""
    body_text: Optional[str] = ""
    date_header: Optional[str] = ""
    auth_results: Optional[str] = ""
    received_spf: Optional[str] = ""
    dkim_signature: Optional[str] = ""
    received_chain: Optional[List[str]] = []
    urls: Optional[List[str]] = []


@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "MailForensix ML Engine & Geolocation Service",
        "version": "1.3.0"
    }


@app.post("/analyze-eml")
async def analyze_eml_file(file: UploadFile = File(...)):
    """
    POST endpoint accepting a raw .eml file upload.
    Runs parser, heuristics, NLP threat evaluation, IP geolocation, timezone inferencing, and weighted risk aggregation.
    """
    try:
        content = await file.read()
        parsed = parse_eml(content)
        return run_full_analysis(parsed)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to process EML file: {str(e)}")


@app.post("/analyze-json")
def analyze_json_payload(payload: JsonAnalysisRequest):
    """
    POST endpoint accepting structured email JSON payload.
    """
    received_chain = payload.received_chain or []
    originating_ip, is_public = extract_originating_ip(
        received_chain,
        auth_results=payload.auth_results or "",
        received_spf=payload.received_spf or ""
    )
    is_cloud, cloud_provider = detect_cloud_webmail(
        payload.from_header or "",
        received_chain,
        payload.auth_results or "",
        ""
    )
    tz_info = extract_timezone_info(payload.date_header or "")

    parsed = {
        "from": payload.from_header,
        "to": "",
        "return_path": payload.return_path,
        "subject": payload.subject,
        "message_id": "",
        "date_header": payload.date_header or "",
        "auth_results": payload.auth_results,
        "dkim_signature": payload.dkim_signature,
        "received_spf": payload.received_spf,
        "received_chain": received_chain,
        "hop_count": len(received_chain),
        "originating_ip_candidate": originating_ip,
        "is_public": is_public,
        "is_cloud_webmail": is_cloud,
        "cloud_provider": cloud_provider,
        "privacy_stripped": is_cloud,
        "timezone_info": tz_info,
        "body_text": payload.body_text,
        "body_html": "",
        "urls": payload.urls or [],
        "domains": []
    }
    return run_full_analysis(parsed)


def run_full_analysis(parsed: dict) -> dict:
    """Core analysis orchestrator."""
    # 1. Run Header Anomaly Heuristics
    header_res = check_header_anomalies(parsed)

    # 2. Run URL Anomaly Heuristics
    url_res = check_url_anomalies(parsed.get("urls", []))

    # 3. Run NLP Intent & Classifier Model
    nlp_res = evaluate_email_nlp(parsed.get("subject", ""), parsed.get("body_text", ""))

    # 4. Run Risk Aggregator with Parsed Metadata
    agg_res = calculate_total_risk(nlp_res, header_res, url_res, graph_mock_score=20.0, parsed_metadata=parsed)

    # 5. Extract Originating Public IP & Resolve Geolocation with Cloud Annotations
    originating_ip = parsed.get("originating_ip_candidate", "Unknown")
    is_public = parsed.get("is_public", False)

    if originating_ip == "Unknown" and parsed.get("received_chain"):
        originating_ip, is_public = extract_originating_ip(
            parsed.get("received_chain"),
            auth_results=parsed.get("auth_results", ""),
            received_spf=parsed.get("received_spf", "")
        )

    geo_resolved = resolve_ip_geolocation(
        originating_ip,
        is_cloud_webmail=parsed.get("is_cloud_webmail", False),
        cloud_provider=parsed.get("cloud_provider", "")
    )

    tz_info = parsed.get("timezone_info", {})

    # Format enriched JSON return structure
    return {
        "total_risk_score": agg_res["total_risk_score"],
        "risk_level": agg_res["risk_level"],
        "sub_scores": {
            "nlp_score": agg_res["sub_scores"]["nlp_score"],
            "header_score": agg_res["sub_scores"]["header_score"],
            "url_score": agg_res["sub_scores"]["url_score"]
        },
        "trace_summary": {
            "sender_domain": header_res.get("from_domain", ""),
            "return_path": header_res.get("return_domain", ""),
            "hop_count": header_res.get("hop_count", 0),
            "originating_ip_candidate": originating_ip,
            "is_public": is_public,
            "is_cloud_webmail": parsed.get("is_cloud_webmail", False),
            "cloud_provider": parsed.get("cloud_provider", ""),
            "privacy_stripped": parsed.get("privacy_stripped", False),
            "date_header": parsed.get("date_header", ""),
            "inferred_timezone": tz_info.get("inferred_timezone", "Unknown"),
            "geolocation": geo_resolved.get("geolocation", {})
        },
        "explainability_highlights": agg_res["explainability_highlights"]
    }
