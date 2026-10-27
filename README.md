# 🛡️ CloudGuard – Capital One Cloud Breach Analysis and Prevention

An interactive, self-contained educational cloud security prototype that demonstrates how cloud misconfigurations led to the landmark **2019 Capital One AWS Data Breach** (~106 million customer records exposed), and how multi-layered cloud security controls prevent unauthorized data access.

> **Zero AWS Deployment & Zero Cloud Expenses**: Everything runs 100% locally on your laptop using Python standard library and an interactive cyber-operations dashboard.

---

## 📌 Executive Summary

In March 2019, an attacker compromised Capital One's cloud environment hosted on Amazon Web Services (AWS), exfiltrating over **106 million credit card applications** and **140,000 Social Security Numbers**. 

The breach did not stem from an AWS flaw; rather, it was caused by **three compounding cloud misconfigurations**:
1. **Server-Side Request Forgery (SSRF)** on an edge EC2 instance running ModSecurity Web Application Firewall.
2. **Unauthenticated Instance Metadata Access (IMDSv1)** at `http://169.254.169.254` that yielded temporary AWS STS credentials for the WAF's instance role (`app-waf-production-role`).
3. **Violation of Least Privilege in IAM**: The WAF instance role was mistakenly granted wildcard administrative permissions (`s3:*` on all resources), enabling the attacker to sync corporate customer credit application archives.

**CloudGuard** reproduces this exact sequence in a safe, visual, interactive sandbox and demonstrates how to remediate each layer.

---

## 🚀 Quickstart (Run in 10 Seconds)

### Prerequisites
- Python 3.8+ installed (no external `pip` packages required!)

### Windows
Double-click `run.bat` or open PowerShell in the project folder:
```powershell
python server.py
```

### macOS / Linux
```bash
chmod +x run.sh
./run.sh
# or simply:
python3 server.py
```

Open your browser to:
👉 **`http://localhost:5000`**

---

## 🎮 Key Capabilities & Features

### 1. Two Live Configurations
* **⚠️ Vulnerable Configuration (Capital One 2019 State)**:
  - WAF reverse proxy allows requests to internal/link-local addresses.
  - AWS IMDSv1 enabled (plain HTTP GET requests without session tokens).
  - IAM Role granted wildcard `s3:*` on `*`.
  - S3 bucket policy lacks VPC Endpoint restrictions.
  - *Result*: The attacker extracts temporary credentials and dumps confidential dummy customer applications.

* **🛡️ Secured Configuration (Multi-Layer Remediation)**:
  - **Layer 1 (SSRF Egress Defense)**: WAF validates upstream targets and rejects `169.254.169.254`, loopback (`127.0.0.1`), and RFC 1918 private subnets.
  - **Layer 2 (Mandatory AWS IMDSv2)**: Rejects plain GET requests with `401 Unauthorized`. Requires a session token via `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds`.
  - **Layer 3 (IAM Least Privilege)**: WAF role is restricted strictly to operational CloudWatch logs (`logs:PutLogEvents`). Access to customer data buckets is denied.
  - **Layer 4 (S3 Bucket Policies)**: Enforces `aws:sourceVpce` conditions so requests originating outside the authorized VPC Endpoint are rejected.

---

### 2. Interactive Breach Pipeline (4-Step Attack Chain)
Users can execute the attack step-by-step or use the **"Auto-Run Full Attack Pipeline"** button:
1. **Step 01 - SSRF Exploitation**: Probe the WAF reverse proxy (`/api/waf/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`) to discover attached role names.
2. **Step 02 - Harvest STS Credentials**: Query the metadata endpoint to extract temporary credentials (`AccessKeyId`, `SecretAccessKey`, `Token`).
3. **Step 03 - S3 Reconnaissance**: Execute `aws s3 ls` with stolen credentials to locate confidential data lakes (`c1-prod-credit-applications`).
4. **Step 04 - Data Exfiltration**: Download `customer_credit_applications_2019.json` and view compromised records in the live exfiltration table.

---

### 3. Interactive Cloud Architecture Topology
An HTML5 Canvas network diagram visualizing:
```
[Attacker (Public Web)]
        │
        ▼ (1. Inbound HTTP / SSRF)
[EC2: ModSecurity WAF Proxy] ────► [AWS IMDS: 169.254.169.254]
        │                                  │ (2. STS Token Broker)
        │                                  ▼
        │                          [AWS IAM & STS Service]
        │
        ▼ (3. Direct S3 Query)
[Amazon S3: c1-prod-credit-applications] (106M Customer Records)
```
- Real-time animated packets travel across the network.
- In **Vulnerable Mode**, red packets penetrate the perimeter and siphon data.
- In **Secured Mode**, glowing green shield barriers intercept and block the attack at each active defense layer.

---

### 4. Interactive AWS CLI Terminal Simulator
A functional in-browser terminal emulator supporting real commands and quick-run chips:
- `curl "http://localhost:5000/api/waf/proxy?url=http://169.254.169.254/latest/meta-data/"`
- `aws sts get-caller-identity`
- `aws iam get-role-policy`
- `aws s3 ls`
- `aws s3 ls s3://c1-prod-credit-applications`
- `aws s3 cp s3://c1-prod-credit-applications/customer_credit_applications_2019.json .`
- `status`
- `switch secured` / `switch vulnerable`

---

### 5. Policy Comparator (IAM & S3 Diffs)
Side-by-side comparison of the vulnerable vs. secured policies with security annotations explaining the dangerous wildcard `s3:*` and the remediated least-privilege scoping.

---

### 6. AWS CloudTrail Audit Logs
Real-time security auditing table capturing every request, source IP, event name (`SSRF_REQUEST_FORWARDED`, `IMDS_CREDENTIALS_HARVESTED`, `IAM_ACCESS_DENIED`, `S3_DATA_EXFILTRATED`), and outcome.

---

## 📂 Project Structure

```
CloudGuard/
├── server.py              # Modular Python server (zero external dependencies)
├── requirements.txt       # Optional dependencies (Python 3.8+ compatibility)
├── run.bat                # Windows 1-click startup launcher
├── run.sh                 # macOS / Linux startup launcher
├── README.md              # Project documentation & presentation guide
├── data/
│   ├── dummy_customers.json # 100% simulated credit card applications (DUMMY DATA)
│   ├── policies.json        # IAM and S3 bucket policies for both scenarios
│   └── breach_info.json     # Historical timeline, CVEs, and NIST remediations
├── static/
│   ├── index.html         # Cybersecurity Operations Center dashboard
│   ├── css/
│   │   └── style.css      # Cyber theme (dark slate, neon accents, responsive)
│   └── js/
│       ├── app.js         # State orchestrator & step-by-step pipeline runner
│       ├── topology.js    # Canvas cloud architecture visualizer
│       └── terminal.js    # In-browser AWS CLI terminal simulator
└── tests/
    └── test_simulation.py # Automated end-to-end verification test suite
```

---

## 🧪 Automated Testing & Verification

Run the comprehensive 12-point automated test suite:
```bash
python tests/test_simulation.py
```

The test verifies:
- Static file serving (HTML, CSS, JS)
- Vulnerable SSRF metadata resolution
- Vulnerable STS key harvesting
- Vulnerable S3 bucket enumeration & data download
- Secured SSRF link-local blocking (HTTP 403)
- Secured IAM Least Privilege enforcement (`AccessDenied`)
- Interactive AWS CLI terminal execution
- CloudTrail audit log recording

---

## 🏛️ Educational Lessons & Real-World Best Practices

| Architecture Layer | 2019 Capital One Flaw | CloudGuard Remediation |
|---|---|---|
| **Edge / Reverse Proxy** | Unrestricted forwarding to arbitrary URLs (CWE-918) | Input validation and egress firewall blocking `169.254.169.254` and private IPs |
| **Compute Instance** | AWS IMDSv1 allowed unauthenticated HTTP GET requests | Enforce **AWS IMDSv2** (`HttpTokens=required`, `HttpPutResponseHopLimit=1`) |
| **Identity & Access** | WAF instance role had wildcard `s3:*` across all buckets | Apply **Principle of Least Privilege**: restrict role strictly to CloudWatch logs |
| **Data Lake (S3)** | S3 buckets had no network perimeter constraints | Enforce **VPC Endpoints** (`aws:sourceVpce`) and Customer Managed KMS Keys (CMKs) |

---

## ⚖️ Disclaimer
*All customer names, Social Security Numbers, addresses, and account numbers generated in this project are entirely fictitious and simulated for academic, educational, and defense-demonstration purposes only.*
