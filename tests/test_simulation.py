#!/usr/bin/env python3
"""
Automated Test Suite for CloudGuard
Validates all attack vectors, defenses, endpoints, and CLI simulations.
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import sys

BASE = 'http://localhost:5000'

def test(name, ok, detail=''):
    mark = '[PASS]' if ok else '[FAIL]'
    print(f"{mark} {name}: {detail}")
    if not ok:
        raise AssertionError(f"Test failed: {name}")

def run_all_tests():
    print("=" * 65)
    print("  RUNNING CLOUDGUARD AUTOMATED VERIFICATION SUITE")
    print("=" * 65)

    # 1. Static Files Serving
    for path in ['/', '/css/style.css', '/js/app.js', '/js/topology.js', '/js/terminal.js']:
        res = urllib.request.urlopen(BASE + path)
        content = res.read()
        test(f"Static File {path}", res.getcode() == 200 and len(content) > 0, f"HTTP {res.getcode()}, {len(content)} bytes")

    # 2. Reset scenario to Vulnerable
    req = urllib.request.Request(
        f"{BASE}/api/config/scenario",
        data=json.dumps({"scenario": "vulnerable"}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    res = urllib.request.urlopen(req)
    test("Scenario Reset to Vulnerable", res.getcode() == 200, "HTTP 200")

    # 3. Status Check
    res = urllib.request.urlopen(f"{BASE}/api/status")
    status = json.loads(res.read().decode("utf-8"))
    test("Status Verification", status["scenario"] == "vulnerable" and status["threat_level"] == "CRITICAL", f"Scenario: {status['scenario']}, Threat: {status['threat_level']}")

    # 4. Vulnerable Step 1: SSRF Probe to 169.254.169.254
    target_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    res = urllib.request.urlopen(f"{BASE}/api/waf/proxy?url={urllib.parse.quote(target_url)}")
    d1 = json.loads(res.read().decode("utf-8"))
    test("Vulnerable Step 1 (SSRF)", d1.get("success") is True and "app-waf-production-role" in str(d1.get("imds_response")), f"Discovered Role: {d1.get('imds_response')}")

    # 5. Vulnerable Step 2: Harvest STS Credentials via IMDS
    target_url2 = "http://169.254.169.254/latest/meta-data/iam/security-credentials/app-waf-production-role"
    res2 = urllib.request.urlopen(f"{BASE}/api/waf/proxy?url={urllib.parse.quote(target_url2)}")
    d2 = json.loads(res2.read().decode("utf-8"))
    stolen_creds = d2.get("imds_response")
    test("Vulnerable Step 2 (Harvest STS)", stolen_creds and "AccessKeyId" in stolen_creds, f"AccessKeyId: {stolen_creds.get('AccessKeyId')}")

    # 6. Vulnerable Step 3: S3 Reconnaissance (ListBuckets)
    req3 = urllib.request.Request(
        f"{BASE}/api/aws/s3",
        data=json.dumps({"action": "ListBuckets", "auth": stolen_creds}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    res3 = urllib.request.urlopen(req3)
    d3 = json.loads(res3.read().decode("utf-8"))
    test("Vulnerable Step 3 (S3 ListBuckets)", d3.get("success") is True and len(d3.get("buckets", [])) >= 4, f"Buckets enumerated: {len(d3.get('buckets', []))}")

    # 7. Vulnerable Step 4: S3 Exfiltration (GetObject)
    req4 = urllib.request.Request(
        f"{BASE}/api/aws/s3",
        data=json.dumps({
            "action": "GetObject",
            "bucket": "c1-prod-credit-applications",
            "key": "customer_credit_applications_2019.json",
            "auth": stolen_creds
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    res4 = urllib.request.urlopen(req4)
    d4 = json.loads(res4.read().decode("utf-8"))
    test("Vulnerable Step 4 (Exfiltrate Records)", d4.get("success") is True and len(d4.get("data", [])) > 0, f"Exfiltrated {d4.get('records_count')} records")

    # 8. Switch to Secured Scenario
    req_sec = urllib.request.Request(
        f"{BASE}/api/config/scenario",
        data=json.dumps({"scenario": "secured"}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    res_sec = urllib.request.urlopen(req_sec)
    test("Switch to Secured Configuration", res_sec.getcode() == 200, "HTTP 200")

    # 9. Secured Step 1: SSRF Egress Filter blocks link-local
    try:
        urllib.request.urlopen(f"{BASE}/api/waf/proxy?url={urllib.parse.quote(target_url)}")
        test("Secured Step 1 (Should Block)", False, "Did not raise 403")
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode("utf-8"))
        test("Secured Step 1 (SSRF Blocked)", e.code == 403 and "CloudGuard SSRF Defense Filter" in body.get("blocked_by", ""), f"HTTP {e.code} - {body.get('reason')}")

    # 10. Secured Step 3: IAM Least Privilege blocks S3 ListBuckets
    try:
        urllib.request.urlopen(req3)
        test("Secured Step 3 (Should Block)", False, "Did not raise 403")
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode("utf-8"))
        test("Secured Step 3 (IAM Blocked)", e.code == 403 and body.get("error_code") == "AccessDenied", f"HTTP {e.code} - {body.get('error_message')[:75]}...")

    # 11. Interactive Terminal Commands
    for cmd in ["aws sts get-caller-identity", "status", "aws s3 ls"]:
        req_cmd = urllib.request.Request(
            f"{BASE}/api/terminal/execute",
            data=json.dumps({"command": cmd}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        res_cmd = urllib.request.urlopen(req_cmd)
        d_cmd = json.loads(res_cmd.read().decode("utf-8"))
        test(f"Terminal Command '{cmd}'", len(d_cmd.get("output", "")) > 0, d_cmd.get("output").splitlines()[0] if d_cmd.get("output") else "")

    # 12. CloudTrail Audit Logs
    res_logs = urllib.request.urlopen(f"{BASE}/api/logs")
    d_logs = json.loads(res_logs.read().decode("utf-8"))
    test("CloudTrail Event Logging", len(d_logs.get("logs", [])) >= 5, f"{len(d_logs.get('logs', []))} audit events logged")

    # 13. Dedicated Backend Reset Test (POST /api/config/reset)
    req_sec = urllib.request.Request(
        f"{BASE}/api/config/scenario",
        data=json.dumps({"scenario": "secured"}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    res_sec = urllib.request.urlopen(req_sec)
    st_sec = json.loads(res_sec.read().decode("utf-8"))["status"]
    assert st_sec["scenario"] == "secured" and st_sec["controls"]["ssrf_protection"] is True

    req_rst = urllib.request.Request(
        f"{BASE}/api/config/reset",
        data=json.dumps({}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    res_rst = urllib.request.urlopen(req_rst)
    d_rst = json.loads(res_rst.read().decode("utf-8"))
    st_rst = d_rst.get("status", {})
    ctrls = st_rst.get("controls", {})

    reset_ok = (
        res_rst.getcode() == 200 and
        d_rst.get("success") is True and
        d_rst.get("scenario") == "vulnerable" and
        st_rst.get("scenario") == "vulnerable" and
        ctrls.get("ssrf_protection") is False and
        ctrls.get("imds_version") == "v1" and
        ctrls.get("iam_least_privilege") is False and
        ctrls.get("s3_bucket_policy") is False and
        st_rst.get("threat_level") == "CRITICAL"
    )
    test("Backend Reset to Vulnerable Baseline", reset_ok, f"Scenario: {d_rst.get('scenario')}, Controls: {ctrls}")

    # 14. Verify SYSTEM_RESET Audit Event
    res_logs_after = urllib.request.urlopen(f"{BASE}/api/logs")
    d_logs_after = json.loads(res_logs_after.read().decode("utf-8"))
    has_reset_event = any(l.get("event_name") == "SYSTEM_RESET" for l in d_logs_after.get("logs", []))
    test("SYSTEM_RESET Audit Event Recorded", has_reset_event, "SYSTEM_RESET event confirmed in audit log")

    # 15. Isolated S3 Bucket-Policy Test (PRD Section 7 & 8)
    # 15.1 Start from a known clean state via reset
    req_clean = urllib.request.Request(
        f"{BASE}/api/config/reset",
        data=json.dumps({}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req_clean)

    # 15.2 Explicitly disable IAM least privilege and enable S3 bucket policy restriction
    req_toggle_iam = urllib.request.Request(
        f"{BASE}/api/config/toggle",
        data=json.dumps({"key": "iam_least_privilege", "value": False}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req_toggle_iam)

    req_toggle_s3 = urllib.request.Request(
        f"{BASE}/api/config/toggle",
        data=json.dumps({"key": "s3_bucket_policy", "value": True}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req_toggle_s3)

    # Verify control state: IAM is broad (False), S3 bucket policy is restricted (True)
    res_st_iso = urllib.request.urlopen(f"{BASE}/api/status")
    d_st_iso = json.loads(res_st_iso.read().decode("utf-8"))
    iso_ctrls = d_st_iso.get("controls", {})
    assert iso_ctrls.get("iam_least_privilege") is False, "IAM least privilege must be False"
    assert iso_ctrls.get("s3_bucket_policy") is True, "S3 bucket policy must be True"

    # 15.3 Attempt GetObject on synthetic target bucket and object
    iso_key = d_st_iso["iam_role"]["credentials_active"]
    req_iso_s3 = urllib.request.Request(
        f"{BASE}/api/aws/s3",
        data=json.dumps({
            "action": "GetObject",
            "bucket": "c1-prod-credit-applications",
            "key": "customer_credit_applications_2019.json",
            "auth": iso_key
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )

    try:
        urllib.request.urlopen(req_iso_s3)
        test("Isolated S3 Bucket Policy Denial (aws:sourceVpce)", False, "Expected HTTP 403 AccessDenied but operation succeeded")
    except urllib.error.HTTPError as e:
        iso_body = json.loads(e.read().decode("utf-8"))
        err_msg = iso_body.get("error_message", "")
        # Prove denial specifically comes from S3 bucket policy condition aws:sourceVpce, NOT IAM
        is_bucket_policy_denial = (
            e.code == 403 and
            iso_body.get("error_code") == "AccessDenied" and
            "aws:sourceVpce" in err_msg and
            "S3 Bucket Policy" in err_msg and
            "identity-based policy" not in err_msg
        )
        test("Isolated S3 Bucket Policy Denial (aws:sourceVpce)", is_bucket_policy_denial, f"HTTP {e.code} - {err_msg}")

    # 16. Automated IMDSv2 Token-Handshake Tests
    # 16.1 Start from a clean baseline and enable IMDSv2 mode
    req_clean_imds = urllib.request.Request(
        f"{BASE}/api/config/reset",
        data=json.dumps({}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req_clean_imds)

    req_enable_imds2 = urllib.request.Request(
        f"{BASE}/api/config/toggle",
        data=json.dumps({"key": "imds_version", "value": "v2"}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    res_toggle_imds2 = urllib.request.urlopen(req_enable_imds2)
    st_imds2 = json.loads(res_toggle_imds2.read().decode("utf-8"))["status"]
    assert st_imds2["controls"]["imds_version"] == "v2", "IMDS version must be v2"
    test("IMDSv2 Mode Enabled (POST /api/config/toggle)", st_imds2["controls"]["imds_version"] == "v2", "imds_version set to v2")

    # 16.2 Request a token using PUT /latest/api/token with a valid TTL header
    req_put_token = urllib.request.Request(
        f"{BASE}/latest/api/token",
        method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
    )
    res_token = urllib.request.urlopen(req_put_token)
    token_val = res_token.read().decode("utf-8").strip()
    # Verify token issuance without depending on any hardcoded token value
    token_ok = res_token.getcode() == 200 and len(token_val) > 0 and isinstance(token_val, str)
    test("IMDSv2 Token Issuance (PUT /latest/api/token)", token_ok, f"HTTP {res_token.getcode()}, Dynamic token length: {len(token_val)}")

    # 16.3 Use the returned token to request IAM role credentials metadata endpoint
    cred_url = f"{BASE}/latest/meta-data/iam/security-credentials/app-waf-production-role"
    req_with_token = urllib.request.Request(
        cred_url,
        headers={"X-aws-ec2-metadata-token": token_val}
    )
    res_with_token = urllib.request.urlopen(req_with_token)
    d_with_token = json.loads(res_with_token.read().decode("utf-8"))
    creds_valid = (
        res_with_token.getcode() == 200 and
        d_with_token.get("Code") == "Success" and
        "AccessKeyId" in d_with_token and
        "SecretAccessKey" in d_with_token and
        "Token" in d_with_token
    )
    test("IMDSv2 Authenticated GET with Dynamic Token", creds_valid, f"HTTP {res_with_token.getcode()}, AccessKeyId: {d_with_token.get('AccessKeyId')}")

    # 16.4 Make the same request without a token and verify HTTP 401
    req_no_token = urllib.request.Request(cred_url)
    try:
        urllib.request.urlopen(req_no_token)
        test("IMDSv2 Unauthenticated GET Blocked", False, "Expected HTTP 401 Unauthorized but request succeeded")
    except urllib.error.HTTPError as e:
        body_no_token = e.read().decode("utf-8")
        test("IMDSv2 Unauthenticated GET Blocked", e.code == 401 and "401" in body_no_token, f"HTTP {e.code} Unauthorized (token missing)")

    # 16.5 Make a request with an invalid token and verify HTTP 401
    invalid_token = f"invalid-token-{token_val[::-1]}"
    req_invalid_token = urllib.request.Request(
        cred_url,
        headers={"X-aws-ec2-metadata-token": invalid_token}
    )
    try:
        urllib.request.urlopen(req_invalid_token)
        test("IMDSv2 Invalid Token GET Blocked", False, "Expected HTTP 401 Unauthorized but request succeeded")
    except urllib.error.HTTPError as e:
        body_invalid_token = e.read().decode("utf-8")
        test("IMDSv2 Invalid Token GET Blocked", e.code == 401 and "401" in body_invalid_token, f"HTTP {e.code} Unauthorized (invalid token)")

    # 16.6 Restore the backend to known baseline so other tests are not affected
    req_restore = urllib.request.Request(
        f"{BASE}/api/config/reset",
        data=json.dumps({}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    res_restore = urllib.request.urlopen(req_restore)
    st_restored = json.loads(res_restore.read().decode("utf-8"))["status"]
    assert st_restored["scenario"] == "vulnerable" and st_restored["controls"]["imds_version"] == "v1"
    test("Backend Restored to Baseline After IMDSv2 Tests", res_restore.getcode() == 200, "Backend cleanly reset to vulnerable baseline")

    print("=" * 65)
    print("  ALL 21 AUTOMATED TESTS PASSED SUCCESSFULLY!")
    print("=" * 65)

if __name__ == '__main__':
    run_all_tests()
