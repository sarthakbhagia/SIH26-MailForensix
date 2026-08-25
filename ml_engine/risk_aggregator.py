def calculate_total_risk(nlp_res: dict, header_res: dict, url_res: dict, graph_mock_score: float = 0.0, parsed_metadata: dict = None) -> dict:
    """
    Computes weighted aggregated risk score, assigns risk level,
    and compiles human-readable Explainable AI (XAI) diagnostic highlights.
    
    Formula:
    Risk = (0.35 * NLP_Score) + (0.30 * Header_Score) + (0.25 * URL_Score) + (0.10 * Graph_Mock_Score)
    """
    nlp_score = nlp_res.get("nlp_score", 0.0)
    header_score = header_res.get("header_score", 0.0)
    url_score = url_res.get("url_score", 0.0)

    # Weighted calculation
    total_risk = (0.35 * nlp_score) + (0.30 * header_score) + (0.25 * url_score) + (0.10 * graph_mock_score)
    total_risk = round(min(100.0, max(0.0, float(total_risk))), 2)

    # Categorize Risk Level
    if total_risk <= 30.0:
        risk_level = "SAFE"
    elif total_risk <= 65.0:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "CRITICAL"

    # Build Explainability Highlights (XAI)
    explainability_highlights = []

    # 1. Cloud Webmail & Timezone Highlights
    if parsed_metadata and parsed_metadata.get("is_cloud_webmail"):
        provider = parsed_metadata.get("cloud_provider", "Cloud Webmail")
        tz_inferred = parsed_metadata.get("timezone_info", {}).get("inferred_timezone", "Unknown")
        ip_cand = parsed_metadata.get("originating_ip_candidate", "")
        explainability_highlights.append(
            f"[Cloud Webmail Notice] Email sent via {provider}. Originating IP ({ip_cand}) is a cloud infrastructure server. Sender local clock timezone inferred: {tz_inferred}."
        )

    # 2. Header Highlights
    header_alerts = header_res.get("alerts", [])
    for alert in header_alerts:
        explainability_highlights.append(f"[Header Anomaly] {alert}")

    # 3. URL Highlights
    url_alerts = url_res.get("alerts", [])
    for alert in url_alerts:
        explainability_highlights.append(f"[URL Threat] {alert}")

    # 4. NLP Intent Highlights
    intents = nlp_res.get("intents", [])
    if intents:
        intent_str = ", ".join(intents)
        explainability_highlights.append(f"[NLP Intent Markers] Detected intent cues: {intent_str}")

    if nlp_score >= 60.0:
        explainability_highlights.append(f"[NLP Threat Classifier] Text body exhibits high phishing probability (Score: {nlp_score})")

    # 5. Summary highlight if no issues found
    if not explainability_highlights:
        explainability_highlights.append("[Clean Audit] No significant header anomalies, malicious URLs, or threat intent markers detected.")

    return {
        "total_risk_score": total_risk,
        "risk_level": risk_level,
        "sub_scores": {
            "nlp_score": round(float(nlp_score), 2),
            "header_score": round(float(header_score), 2),
            "url_score": round(float(url_score), 2),
            "graph_mock_score": round(float(graph_mock_score), 2)
        },
        "explainability_highlights": explainability_highlights
    }
