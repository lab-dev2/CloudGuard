#!/usr/bin/env python3
"""
CloudGuard: Capital One Cloud Breach Analysis and Prevention Prototype
Demonstrates SSRF -> AWS IMDSv1 Credential Theft -> Over-privileged IAM S3 Exfiltration
and Multi-Layered Remediation (SSRF Egress Filtering, IMDSv2, Least Privilege IAM, S3 Bucket Policies).

Runs locally with Python standard library. No external pip dependencies required.
"""

import http.server
import socketserver
import json
import urllib.parse
import os
import sys
import time
import uuid
import datetime
import mimetypes

PORT = 5000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Load configuration and mock datasets
def load_json(filepath, default_val=None):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Could not load {filepath}: {e}")
        return default_val if default_val is not None else {}

DUMMY_CUSTOMERS = load_json(os.path.join(DATA_DIR, "dummy_customers.json"), [])
POLICIES_DATA = load_json(os.path.join(DATA_DIR, "policies.json"), {})
BREACH_INFO = load_json(os.path.join(DATA_DIR, "breach_info.json"), {})

# In-memory Cloud State
class CloudGuardState:
    def __init__(self):
        self.scenario = "vulnerable"  # "vulnerable" or "secured" or "custom"
        self.ssrf_protection = False
        self.imds_version = "v1"       # "v1" or "v2"
        self.iam_least_privilege = False
        self.s3_bucket_policy_restricted = False
        
        # Credentials state
        self.role_name = "app-waf-production-role"
        self.role_arn = "arn:aws:iam::123456789012:role/app-waf-production-role"
        self.instance_id = "i-0b73c21a9e88d40fa"
        self.valid_key_ids = set()
        self.active_credentials = self._generate_credentials()
        self.active_tokens = {}  # token -> expiration timestamp
        
        # CloudTrail Audit Logs
        self.audit_logs = []
        self.add_log("SYSTEM", "CloudGuard initialized in VULNERABLE configuration mode.", "SUCCESS", "127.0.0.1")

    def set_scenario(self, scenario_name):
        if scenario_name == "vulnerable":
            self.scenario = "vulnerable"
            self.ssrf_protection = False
            self.imds_version = "v1"
            self.iam_least_privilege = False
            self.s3_bucket_policy_restricted = False
            self.add_log("CONFIG_CHANGE", "Environment switched to VULNERABLE configuration (Capital One 2019 baseline).", "WARNING", "127.0.0.1")
        elif scenario_name == "secured":
            self.scenario = "secured"
            self.ssrf_protection = True
            self.imds_version = "v2"
            self.iam_least_privilege = True
            self.s3_bucket_policy_restricted = True
            self.add_log("CONFIG_CHANGE", "Environment switched to SECURED configuration (Multi-layer remediation active).", "SUCCESS", "127.0.0.1")

    def toggle(self, key, value):
        self.scenario = "custom"
        if key == "ssrf_protection":
            self.ssrf_protection = bool(value)
            self.add_log("DEFENSE_TOGGLE", f"SSRF Egress Filter set to {self.ssrf_protection}", "INFO", "127.0.0.1")
        elif key == "imds_version":
            self.imds_version = "v2" if str(value).lower() in ("v2", "true", "2") else "v1"
            self.add_log("DEFENSE_TOGGLE", f"IMDS Version set to {self.imds_version.upper()}", "INFO", "127.0.0.1")
        elif key == "iam_least_privilege":
            self.iam_least_privilege = bool(value)
            self.add_log("DEFENSE_TOGGLE", f"IAM Least Privilege set to {self.iam_least_privilege}", "INFO", "127.0.0.1")
        elif key == "s3_bucket_policy":
            self.s3_bucket_policy_restricted = bool(value)
            self.add_log("DEFENSE_TOGGLE", f"S3 Bucket VPCE Restriction set to {self.s3_bucket_policy_restricted}", "INFO", "127.0.0.1")

    def _generate_credentials(self):
        token_suffix = uuid.uuid4().hex[:12].upper()
        now = datetime.datetime.now(datetime.timezone.utc)
        exp = now + datetime.timedelta(hours=6)
        key_id = f"ASIA{token_suffix}"
        self.valid_key_ids.add(key_id)
        return {
            "Code": "Success",
            "LastUpdated": now.isoformat(),
            "Type": "AWS-HMAC",
            "AccessKeyId": key_id,
            "SecretAccessKey": f"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY{token_suffix[:4]}",
            "Token": f"FQoGZXIvYXdzEM3//////////wEaEG{uuid.uuid4().hex}{uuid.uuid4().hex}==",
            "Expiration": exp.isoformat()
        }

    def generate_imds_token(self, ttl_seconds):
        token = f"aws-token-{uuid.uuid4().hex}"
        self.active_tokens[token] = time.time() + ttl_seconds
        return token

    def is_token_valid(self, token):
        if not token:
            return False
        exp = self.active_tokens.get(token)
        if exp and exp > time.time():
            return True
        return False

    def add_log(self, event_name, details, status, source_ip="198.51.100.42"):
        log_entry = {
            "id": f"log-{uuid.uuid4().hex[:8]}",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "event_name": event_name,
            "source_ip": source_ip,
            "status": status,
            "details": details
        }
        self.audit_logs.insert(0, log_entry)
        if len(self.audit_logs) > 100:
            self.audit_logs.pop()
        return log_entry

STATE = CloudGuardState()


class CloudGuardRequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    HTTP Handler providing both Static Web serving and CloudGuard REST APIs.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def log_message(self, format, *args):
        # Concise server console logging
        sys.stderr.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {format % args}\n")

    def send_json(self, data, status_code=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text, status_code=200, content_type="text/plain"):
        body = text.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        self.end_headers()

    # -------------------------------------------------------------
    # PUT: Used for AWS IMDSv2 Token Acquisition
    # -------------------------------------------------------------
    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/latest/api/token":
            # IMDSv2 Token generation
            ttl_header = self.headers.get("X-aws-ec2-metadata-token-ttl-seconds")
            if not ttl_header:
                STATE.add_log("IMDSv2_TOKEN_REJECTED", "Missing X-aws-ec2-metadata-token-ttl-seconds header", "FAILURE", self.client_address[0])
                self.send_text("400 Bad Request: Missing X-aws-ec2-metadata-token-ttl-seconds header", 400)
                return

            try:
                ttl = int(ttl_header)
                if ttl < 1 or ttl > 21600:
                    raise ValueError()
            except ValueError:
                self.send_text("400 Bad Request: TTL must be an integer between 1 and 21600 seconds", 400)
                return

            token = STATE.generate_imds_token(ttl)
            STATE.add_log("IMDSv2_TOKEN_ISSUED", f"Issued IMDSv2 session token (TTL: {ttl}s)", "SUCCESS", self.client_address[0])
            self.send_text(token, 200)
            return

        self.send_text("404 Not Found", 404)

    # -------------------------------------------------------------
    # POST: Configuration changes, S3 calls, Terminal execution
    # -------------------------------------------------------------
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            req_data = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            req_data = {}

        # 1. Update Scenario (Vulnerable vs Secured)
        if path == "/api/config/scenario":
            scenario = req_data.get("scenario")
            if scenario in ["vulnerable", "secured"]:
                STATE.set_scenario(scenario)
                self.send_json({"success": True, "scenario": STATE.scenario, "status": self._get_status_dict()})
            else:
                self.send_json({"error": "Invalid scenario name. Use 'vulnerable' or 'secured'."}, 400)
            return

        # 2. Toggle Individual Security Features
        if path == "/api/config/toggle":
            key = req_data.get("key")
            value = req_data.get("value")
            if key in ["ssrf_protection", "imds_version", "iam_least_privilege", "s3_bucket_policy"]:
                STATE.toggle(key, value)
                self.send_json({"success": True, "toggled": key, "value": value, "status": self._get_status_dict()})
            else:
                self.send_json({"error": "Invalid toggle key."}, 400)
            return

        # 3. Clear CloudTrail Audit Logs
        if path == "/api/logs/clear":
            STATE.audit_logs.clear()
            STATE.add_log("LOGS_CLEARED", "CloudTrail audit log history was purged.", "INFO", self.client_address[0])
            self.send_json({"success": True, "message": "Audit logs cleared."})
            return

        # 4. AWS S3 API Simulation (ListBuckets, ListObjects, GetObject)
        if path == "/api/aws/s3":
            action = req_data.get("action", "ListBuckets")
            bucket = req_data.get("bucket", "")
            key = req_data.get("key", "")
            auth_header = req_data.get("auth", {})
            stolen_token = auth_header.get("Token") or req_data.get("token")
            stolen_key_id = auth_header.get("AccessKeyId") or req_data.get("access_key_id")

            # Check if caller has valid STS credentials from the WAF role
            is_valid_key = (
                stolen_key_id == STATE.active_credentials["AccessKeyId"] or
                stolen_key_id in STATE.valid_key_ids or
                (isinstance(stolen_key_id, str) and stolen_key_id.startswith("ASIA"))
            )
            if not is_valid_key:
                STATE.add_log("S3_AUTH_FAILED", f"Unauthorized S3 call ({action}): Invalid or missing STS access key", "FAILURE", self.client_address[0])
                self.send_json({
                    "success": False,
                    "error_code": "InvalidAccessKeyId",
                    "error_message": "The AWS Access Key Id you provided does not exist in our records."
                }, 403)
                return

            # Role identity check & IAM Policy Evaluation
            if STATE.iam_least_privilege:
                # SECURED: IAM Role only has logs:*, completely denied from s3:*
                STATE.add_log("IAM_ACCESS_DENIED", f"User {STATE.role_name} denied action s3:{action} by IAM policy (Least Privilege)", "DENIED", self.client_address[0])
                self.send_json({
                    "success": False,
                    "error_code": "AccessDenied",
                    "error_message": f"An error occurred (AccessDenied) when calling the {action} operation: User: {STATE.role_arn} is not authorized to perform: s3:{action} because no identity-based policy allows the s3:{action} action."
                }, 403)
                return

            # If IAM is vulnerable (s3:* allowed), check S3 Bucket Policy (VPC Endpoint condition)
            if STATE.s3_bucket_policy_restricted and bucket in ["c1-prod-credit-applications", "c1-customer-pii-vault"]:
                STATE.add_log("S3_BUCKET_POLICY_DENIED", f"Access to s3://{bucket} rejected by S3 Bucket Policy (VPC Endpoint required)", "DENIED", self.client_address[0])
                self.send_json({
                    "success": False,
                    "error_code": "AccessDenied",
                    "error_message": f"An error occurred (AccessDenied) when calling the {action} operation: Access Denied by S3 Bucket Policy condition 'aws:sourceVpce' (VPC Endpoint mismatch)."
                }, 403)
                return

            # If both are bypassed/vulnerable -> Operation succeeds!
            if action == "ListBuckets":
                STATE.add_log("S3_LIST_BUCKETS_SUCCESS", f"Caller enumerated S3 buckets using stolen {STATE.role_name} credentials", "EXPLOITED", self.client_address[0])
                buckets = POLICIES_DATA.get("buckets", [])
                self.send_json({
                    "success": True,
                    "action": "ListBuckets",
                    "owner": {"DisplayName": "c1-cloud-admin", "ID": "a98c0b2d1ef"},
                    "buckets": buckets
                })
                return

            elif action == "ListObjects":
                bucket_info = next((b for b in POLICIES_DATA.get("buckets", []) if b["name"] == bucket), None)
                if not bucket_info:
                    self.send_json({"success": False, "error_code": "NoSuchBucket", "error_message": "The specified bucket does not exist"}, 404)
                    return
                STATE.add_log("S3_LIST_OBJECTS_SUCCESS", f"Caller enumerated objects in s3://{bucket}", "EXPLOITED", self.client_address[0])
                self.send_json({
                    "success": True,
                    "bucket": bucket,
                    "contents": [{"Key": fn, "Size": 1405230, "StorageClass": "STANDARD"} for fn in bucket_info.get("files", [])]
                })
                return

            elif action == "GetObject":
                STATE.add_log("S3_DATA_EXFILTRATED", f"EXFILTRATION: Downloaded s3://{bucket}/{key} containing customer records!", "BREACH_CRITICAL", self.client_address[0])
                self.send_json({
                    "success": True,
                    "bucket": bucket,
                    "key": key,
                    "data": DUMMY_CUSTOMERS,
                    "records_count": len(DUMMY_CUSTOMERS),
                    "note": "SIMULATED EXFILTRATED DATA: In the actual 2019 Capital One breach, ~106 million customer applications were dumped."
                })
                return

            self.send_json({"error": f"Unknown S3 action '{action}'"}, 400)
            return

        # 5. Interactive AWS CLI Terminal Command Executor
        if path == "/api/terminal/execute":
            cmd = req_data.get("command", "").strip()
            res = self._handle_terminal_command(cmd)
            self.send_json(res)
            return

        self.send_text("404 Not Found", 404)

    # -------------------------------------------------------------
    # GET: Status, WAF Proxy (SSRF Target), IMDS metadata, Static files
    # -------------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. CloudGuard Status & Metrics API
        if path == "/api/status":
            self.send_json(self._get_status_dict())
            return

        # 2. CloudTrail Audit Logs API
        if path == "/api/logs":
            self.send_json({"logs": STATE.audit_logs})
            return

        # 3. Policies & Differences API
        if path == "/api/policies":
            self.send_json(POLICIES_DATA)
            return

        # 4. Breach Educational Breakdown API
        if path == "/api/breach-info":
            self.send_json(BREACH_INFO)
            return

        # 5. Customer Records (Only accessible directly if authorized)
        if path == "/api/customers":
            self.send_json(DUMMY_CUSTOMERS)
            return

        # 6. Simulated WAF / Reverse Proxy (The SSRF Injection Point!)
        if path == "/api/waf/proxy":
            target_url = query.get("url", [""])[0]
            if not target_url:
                self.send_json({
                    "error": "Missing 'url' parameter. Usage: /api/waf/proxy?url=http://example.com"
                }, 400)
                return

            res = self._handle_waf_proxy(target_url)
            self.send_json(res, status_code=res.get("http_status", 200))
            return

        # 7. Simulated AWS IMDS Endpoint: /latest/meta-data/...
        if path.startswith("/latest/meta-data"):
            res = self._handle_imds_request(path)
            if isinstance(res, dict):
                self.send_json(res, status_code=res.get("status_code", 200))
            else:
                self.send_text(res)
            return

        # 8. Static file fallback
        super().do_GET()

    # -------------------------------------------------------------
    # Helper: Return System Status
    # -------------------------------------------------------------
    def _get_status_dict(self):
        return {
            "scenario": STATE.scenario,
            "threat_level": "CRITICAL" if not (STATE.ssrf_protection and STATE.imds_version == "v2" and STATE.iam_least_privilege) else "SECURED",
            "controls": {
                "ssrf_protection": STATE.ssrf_protection,
                "imds_version": STATE.imds_version,
                "iam_least_privilege": STATE.iam_least_privilege,
                "s3_bucket_policy": STATE.s3_bucket_policy_restricted
            },
            "iam_role": {
                "name": STATE.role_name,
                "arn": STATE.role_arn,
                "instance_id": STATE.instance_id,
                "credentials_active": {
                    "AccessKeyId": STATE.active_credentials["AccessKeyId"],
                    "Expiration": STATE.active_credentials["Expiration"]
                }
            },
            "audit_log_count": len(STATE.audit_logs)
        }

    # -------------------------------------------------------------
    # Helper: Handle WAF Reverse Proxy with SSRF Vulnerability/Defense
    # -------------------------------------------------------------
    def _handle_waf_proxy(self, target_url):
        # Parse the requested target
        parsed = urllib.parse.urlsplit(target_url)
        hostname = parsed.hostname or ""
        path = parsed.path
        if not path:
            path = "/"
        if parsed.query:
            path += f"?{parsed.query}"

        # SSRF DEFENSE CHECK
        if STATE.ssrf_protection:
            # Check for link-local AWS metadata (169.254.169.254) and localhost
            blocked_hosts = ["169.254.169.254", "127.0.0.1", "localhost", "0.0.0.0", "::1", "metadata.google.internal"]
            is_blocked = (hostname in blocked_hosts) or hostname.startswith("169.254.") or hostname.startswith("10.") or hostname.startswith("192.168.")
            
            if is_blocked:
                STATE.add_log("SSRF_ATTACK_BLOCKED", f"WAF Egress Firewall blocked malicious request to {target_url}", "BLOCKED", self.client_address[0])
                return {
                    "success": False,
                    "http_status": 403,
                    "blocked_by": "CloudGuard SSRF Defense Filter",
                    "target_url": target_url,
                    "reason": f"Access to link-local and private network host '{hostname}' is denied by egress firewall security policy.",
                    "educational_note": "In a hardened architecture, reverse proxies are forbidden from routing outbound requests to the internal AWS metadata address 169.254.169.254."
                }

        # If SSRF protection is disabled -> Attacker can query internal resources!
        STATE.add_log("SSRF_REQUEST_FORWARDED", f"WAF forwarded unvalidated SSRF query to: {target_url}", "EXPLOITED", self.client_address[0])

        # If target points to IMDS (169.254.169.254 or localhost metadata)
        if hostname in ["169.254.169.254", "localhost", "127.0.0.1", ""]:
            # Evaluate against IMDS
            imds_res = self._evaluate_imds(path, self.headers.get("X-aws-ec2-metadata-token"))
            return {
                "success": imds_res.get("status_code", 200) == 200,
                "http_status": imds_res.get("status_code", 200),
                "target_url": target_url,
                "vulnerability": "SSRF (Server-Side Request Forgery) Successful",
                "imds_response": imds_res.get("body"),
                "educational_note": "The vulnerable reverse proxy blindly made an HTTP request on behalf of the attacker to the internal AWS EC2 metadata IP (169.254.169.254)."
            }

        # Generic simulated external response
        return {
            "success": True,
            "http_status": 200,
            "target_url": target_url,
            "simulated_upstream_response": f"HTTP 200 OK from {hostname}"
        }

    # -------------------------------------------------------------
    # Helper: Internal IMDS evaluation logic
    # -------------------------------------------------------------
    def _evaluate_imds(self, path, token_header=None):
        # Clean path
        path = path.strip("/")
        
        # Check IMDSv2 enforcement
        if STATE.imds_version == "v2":
            if not token_header or not STATE.is_token_valid(token_header):
                STATE.add_log("IMDSv2_TOKEN_MISSING", f"Unauthorized GET to /{path} without valid IMDSv2 session token", "BLOCKED", self.client_address[0])
                return {
                    "status_code": 401,
                    "body": "401 - Unauthorized: AWS IMDSv2 requires a valid session token passed via the 'X-aws-ec2-metadata-token' header. Plain GET requests without token are rejected."
                }

        # Metadata routing
        if path == "latest/meta-data" or path == "latest/meta-data/":
            return {
                "status_code": 200,
                "body": "ami-id\ninstance-id\ninstance-type\nlocal-ipv4\npublic-ipv4\niam/\nplacement/"
            }
        elif path == "latest/meta-data/iam" or path == "latest/meta-data/iam/":
            return {
                "status_code": 200,
                "body": "info\nsecurity-credentials/"
            }
        elif path == "latest/meta-data/iam/security-credentials" or path == "latest/meta-data/iam/security-credentials/":
            return {
                "status_code": 200,
                "body": STATE.role_name
            }
        elif path == f"latest/meta-data/iam/security-credentials/{STATE.role_name}":
            STATE.add_log("IMDS_CREDENTIALS_HARVESTED", f"Temporary STS credentials for IAM role '{STATE.role_name}' were retrieved via IMDS", "CRITICAL_EXPLOITED", self.client_address[0])
            return {
                "status_code": 200,
                "body": STATE.active_credentials
            }
        elif path == "latest/meta-data/instance-id":
            return {"status_code": 200, "body": STATE.instance_id}
        else:
            return {"status_code": 404, "body": "404 - Not Found"}

    def _handle_imds_request(self, full_path):
        token = self.headers.get("X-aws-ec2-metadata-token")
        eval_res = self._evaluate_imds(full_path, token)
        return eval_res.get("body")

    # -------------------------------------------------------------
    # Helper: Interactive AWS CLI Terminal Simulator
    # -------------------------------------------------------------
    def _handle_terminal_command(self, cmd):
        if not cmd:
            return {"output": ""}

        parts = cmd.strip().split()
        base = parts[0].lower()

        # Command: clear
        if base == "clear":
            return {"clear": True, "output": ""}

        # Command: help
        if base == "help":
            return {
                "output": """Available CloudGuard Terminal Commands:
  curl <url>                      Simulate HTTP request (e.g. curl http://169.254.169.254/latest/meta-data/)
  curl -H "X-aws-ec2-metadata-token: <tok>" <url>  Simulate IMDSv2 request
  aws sts get-caller-identity     Check active IAM identity from stolen credentials
  aws iam get-role-policy         Inspect permissions attached to app-waf-production-role
  aws s3 ls                       List all S3 buckets (ListAllMyBuckets)
  aws s3 ls s3://<bucket>         List objects inside a specific S3 bucket
  aws s3 cp s3://<bucket>/<file>  Download object from bucket
  aws s3 sync s3://<bucket>       Sync entire S3 bucket locally
  status                          Display CloudGuard defense posture
  switch vulnerable               Switch to Vulnerable configuration (Capital One 2019)
  switch secured                  Switch to Secured configuration (Remediated)
  clear                           Clear terminal screen"""
            }

        # Command: status
        if base == "status":
            st = self._get_status_dict()
            return {
                "output": f"""[CloudGuard Security Status]
Scenario:            {st['scenario'].upper()}
Overall Threat:      {st['threat_level']}
SSRF Egress Defense: {'ENABLED (Protected)' if st['controls']['ssrf_protection'] else 'DISABLED (Vulnerable)'}
IMDS Version:        {st['controls']['imds_version'].upper()} ({'Protected' if st['controls']['imds_version'] == 'v2' else 'Vulnerable to SSRF'})
IAM Least Privilege: {'ENFORCED (Scoped logs:*)' if st['controls']['iam_least_privilege'] else 'VIOLATED (Wildcard s3:*)'}
S3 Bucket Boundary:  {'STRICT VPC-ENDPOINT' if st['controls']['s3_bucket_policy'] else 'OPEN'}"""
            }

        # Command: switch <vulnerable|secured>
        if base == "switch" and len(parts) > 1:
            target = parts[1].lower()
            if target in ["vulnerable", "secured"]:
                STATE.set_scenario(target)
                return {"output": f"Configuration successfully changed to: {target.upper()}"}
            return {"output": "Usage: switch [vulnerable|secured]"}

        # Command: curl
        if base == "curl":
            target_url = None
            token = None
            i = 1
            while i < len(parts):
                if parts[i] == "-H" and i + 1 < len(parts):
                    header_val = parts[i+1].strip('"\'')
                    if "x-aws-ec2-metadata-token:" in header_val.lower():
                        token = header_val.split(":", 1)[1].strip()
                    i += 2
                elif not parts[i].startswith("-"):
                    target_url = parts[i].strip('"\'')
                    i += 1
                else:
                    i += 1

            if not target_url:
                return {"output": "curl: no URL specified"}

            # If user queries the WAF proxy endpoint
            if "/api/waf/proxy" in target_url:
                parsed_q = urllib.parse.urlsplit(target_url)
                qs = urllib.parse.parse_qs(parsed_q.query)
                dest = qs.get("url", [""])[0]
                waf_res = self._handle_waf_proxy(dest)
                if not waf_res.get("success"):
                    return {"output": f"HTTP/1.1 {waf_res.get('http_status', 403)} Forbidden\n{json.dumps(waf_res, indent=2)}"}
                return {"output": f"HTTP/1.1 {waf_res.get('http_status', 200)} OK\n{json.dumps(waf_res.get('imds_response', waf_res), indent=2)}"}

            # Direct query to IMDS emulation
            if "169.254.169.254" in target_url:
                # If SSRF protection is ON and this was called as if through proxy
                if STATE.ssrf_protection:
                    return {"output": "HTTP/1.1 403 Forbidden: Destination 169.254.169.254 blocked by egress firewall rules."}
                
                path = target_url.split("169.254.169.254", 1)[1]
                imds_eval = self._evaluate_imds(path, token)
                body = imds_eval.get("body")
                if isinstance(body, dict):
                    return {"output": json.dumps(body, indent=2)}
                return {"output": str(body)}

            return {"output": f"curl: (7) Failed to connect to {target_url}"}

        # Command: aws sts get-caller-identity
        if base == "aws" and len(parts) >= 3 and parts[1] == "sts" and parts[2] == "get-caller-identity":
            return {
                "output": json.dumps({
                    "UserId": f"AROAVULNERABLEKEY:{STATE.instance_id}",
                    "Account": "123456789012",
                    "Arn": f"arn:aws:sts::123456789012:assumed-role/{STATE.role_name}/{STATE.instance_id}"
                }, indent=2)
            }

        # Command: aws iam get-role-policy
        if base == "aws" and len(parts) >= 3 and parts[1] == "iam" and parts[2] == "get-role-policy":
            scenario_key = "secured" if STATE.iam_least_privilege else "vulnerable"
            policy = POLICIES_DATA.get("scenarios", {}).get(scenario_key, {}).get("iam_policy", {})
            return {
                "output": json.dumps({
                    "RoleName": STATE.role_name,
                    "PolicyName": f"{STATE.role_name}-policy",
                    "PolicyDocument": policy
                }, indent=2)
            }

        # Command: aws s3 ls
        if base == "aws" and len(parts) >= 3 and parts[1] == "s3" and parts[2] == "ls":
            # If target bucket specified: aws s3 ls s3://bucket
            if len(parts) >= 4 and parts[3].startswith("s3://"):
                target_bucket = parts[3].replace("s3://", "").strip("/")
                if STATE.iam_least_privilege:
                    return {
                        "output": f"An error occurred (AccessDenied) when calling the ListObjectsV2 operation: User: {STATE.role_arn} is not authorized to perform: s3:ListBucket on resource: arn:aws:s3:::{target_bucket}"
                    }
                if STATE.s3_bucket_policy_restricted and target_bucket in ["c1-prod-credit-applications", "c1-customer-pii-vault"]:
                    return {
                        "output": f"An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied by S3 Bucket Policy (Condition aws:sourceVpce not met)."
                    }
                b_info = next((b for b in POLICIES_DATA.get("buckets", []) if b["name"] == target_bucket), None)
                if not b_info:
                    return {"output": f"An error occurred (NoSuchBucket) when calling the ListObjectsV2 operation: The specified bucket '{target_bucket}' does not exist."}
                out_lines = [f"2019-03-22 09:14:22     1405230 {fn}" for fn in b_info.get("files", [])]
                return {"output": "\n".join(out_lines)}

            # aws s3 ls (List all buckets)
            if STATE.iam_least_privilege:
                return {
                    "output": f"An error occurred (AccessDenied) when calling the ListBuckets operation: User: {STATE.role_arn} is not authorized to perform: s3:ListAllMyBuckets because no identity-based policy allows the s3:ListAllMyBuckets action."
                }
            
            # Vulnerable mode: list buckets
            buckets = POLICIES_DATA.get("buckets", [])
            lines = [f"2019-01-15 12:00:00 {b['name']}" for b in buckets]
            return {"output": "\n".join(lines)}

        # Command: aws s3 cp or aws s3 sync
        if base == "aws" and len(parts) >= 3 and parts[1] == "s3" and parts[2] in ["cp", "sync"]:
            if len(parts) < 4:
                return {"output": "usage: aws s3 cp <target> <destination>"}
            s3_path = parts[3]
            target_bucket = s3_path.replace("s3://", "").split("/")[0]
            
            if STATE.iam_least_privilege:
                return {
                    "output": f"An error occurred (AccessDenied) when calling the GetObject operation: User: {STATE.role_arn} is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::{target_bucket}/*"
                }
            if STATE.s3_bucket_policy_restricted and target_bucket in ["c1-prod-credit-applications", "c1-customer-pii-vault"]:
                return {
                    "output": f"An error occurred (AccessDenied) when calling the GetObject operation: Access Denied by S3 Bucket Policy (VPC Endpoint required)."
                }

            # If exfiltrating customer applications
            STATE.add_log("S3_EXFILTRATION_CLI", f"EXFILTRATION: Downloaded {s3_path} via AWS CLI!", "BREACH_CRITICAL", self.client_address[0])
            first_rec = DUMMY_CUSTOMERS[0] if DUMMY_CUSTOMERS else {}
            return {
                "output": f"""download: {s3_path} to ./customer_records_2019.json
[+] Extracted {len(DUMMY_CUSTOMERS)} records. Sample Record Exfiltrated:
{json.dumps(first_rec, indent=2)}
[!] WARNING: In 2019, Capital One exposed ~106M customer credit records through this exact mechanism."""
            }

        return {"output": f"bash: command not recognized: '{cmd}'. Type 'help' for supported commands."}


def run_server(port=PORT):
    # Ensure stdout/stderr handle UTF-8 properly on Windows
    if sys.platform.startswith('win'):
        try:
            if hasattr(sys.stdout, 'reconfigure'):
                sys.stdout.reconfigure(encoding='utf-8')
            if hasattr(sys.stderr, 'reconfigure'):
                sys.stderr.reconfigure(encoding='utf-8')
        except Exception:
            pass

    # Enable socket address reuse to prevent "Address already in use" errors on restart
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", port), CloudGuardRequestHandler) as httpd:
        print("=" * 70)
        print("  [+] CloudGuard: Capital One Cloud Breach Simulator & Defense Lab")
        print(f"  [+] Server running at: http://localhost:{port}")
        print("  [+] Open your browser to access the interactive dashboard")
        print("  [+] Press Ctrl+C to stop the server")
        print("=" * 70)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down CloudGuard server cleanly...")
            httpd.server_close()


if __name__ == "__main__":
    port_arg = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else PORT
    run_server(port_arg)
