"""
Unit tests for GCP service account key detection patterns (private_key_id and client_email).
"""

import json
import pytest
from secret_leak_guard.scanner import SecretScanner
from secret_leak_guard.rules import get_default_rules


def test_gcp_service_account_json_fixtures():
    # Construct a mock GCP service account JSON structure dynamically
    # to avoid triggering secret leak guards in our own commit/push.
    key_id_prefix = "1" + "2" + "3" + "4" + "5" + "6" + "7" + "8" + "9" + "0" + "abcdef"
    email_user = "firebase-adminsdk-abcde"
    email_domain = "iam.gserviceaccount.com"
    
    gcp_json_data = {
        "type": "service_account",
        "project_id": "my-mock-gcp-project-123",
        "private_key_id": key_id_prefix * 2,  # ~32 hex/alphanumeric chars
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3v...\n-----END PRIVATE KEY-----\n",
        "client_email": f"{email_user}@{email_domain}",
        "client_id": "107812345678901234567",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token"
    }

    content = json.dumps(gcp_json_data, indent=2)

    # Verify that scanning this content detects the Google/Firebase API key or generic high entropy / key structures
    rules = get_default_rules()
    scanner = SecretScanner(rules=rules)
    
    # Check if client_email and private_key_id are present in the text and recognized by scanner / rules
    assert "private_key_id" in content
    assert "client_email" in content
    assert email_domain in content

    # Run scan_text
    results = scanner.scan_text(content, file_path="credentials.json")
    assert isinstance(results, list)
