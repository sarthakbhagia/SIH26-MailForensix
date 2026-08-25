import json
from email_parser import parse_eml
from app import run_full_analysis

def test_webmail_enrichment():
    print("==========================================================")
    print("   RUNNING CLOUD WEBMAIL & TIMEZONE ENRICHMENT TESTS     ")
    print("==========================================================\n")

    # Read Test.eml from Downloads
    eml_path = r"C:\Users\KEDAR\Downloads\Test.eml"
    print(f"Loading test file: {eml_path}...")
    with open(eml_path, "rb") as f:
        content = f.read()

    parsed = parse_eml(content)
    analysis = run_full_analysis(parsed)

    print("\n--- Extracted Trace Summary ---")
    print(json.dumps(analysis["trace_summary"], indent=2))

    print("\n--- Explainability Highlights ---")
    for h in analysis["explainability_highlights"]:
        print(f" -> {h}")

    # Assertions
    trace = analysis["trace_summary"]
    assert trace["is_cloud_webmail"] is True, "Expected is_cloud_webmail == True"
    assert "Google" in trace["cloud_provider"], f"Expected Google in cloud_provider, got '{trace['cloud_provider']}'"
    assert "+05:30" in trace["inferred_timezone"], f"Expected '+05:30' in inferred_timezone, got '{trace['inferred_timezone']}'"

    print("\n==========================================================")
    print("      ALL CLOUD WEBMAIL & TIMEZONE TESTS PASSED!          ")
    print("==========================================================")

if __name__ == "__main__":
    test_webmail_enrichment()
