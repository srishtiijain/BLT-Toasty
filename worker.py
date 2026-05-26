"""
Cloudflare Worker for Toasty - AI Code Reviewer Backend

This worker handles API requests for the Toasty AI code review service.
It provides endpoints for code analysis, health checks, and status monitoring.

Security scanning is done in three layers:
  1. Bandit-style rules  - pattern matching for Python security issues
  2. Semgrep-style rules - OWASP Top 10 pattern detection
  3. Gemini AI          - AI-driven explanation and reasoning for findings
"""

from js import Response, Headers, fetch
import json
import re
from datetime import datetime, timezone

# Maximum request body size in bytes (1MB)
MAX_BODY_SIZE = 1024 * 1024

# Gemini API endpoint
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"


# ---------------------------------------------------------------------------
# LAYER 1: BANDIT-STYLE RULES
# These mimic what the real Bandit tool does — look for dangerous Python
# patterns like hardcoded passwords, use of eval(), unsafe imports, etc.
# ---------------------------------------------------------------------------

BANDIT_RULES = [
    {
        "id": "B101",
        "name": "assert_used",
        "pattern": r"\bassert\b",
        "severity": "LOW",
        "message": "Use of assert detected. Assertions are removed when Python is run with optimizations (-O flag), which can disable security checks.",
        "cwe": "CWE-617",
    },
    {
        "id": "B102",
        "name": "exec_used",
        "pattern": r"\bexec\s*\(",
        "severity": "HIGH",
        "message": "Use of exec() detected. This can execute arbitrary code and is a major security risk.",
        "cwe": "CWE-78",
    },
    {
        "id": "B103",
        "name": "eval_used",
        "pattern": r"\beval\s*\(",
        "severity": "HIGH",
        "message": "Use of eval() detected. This executes arbitrary Python expressions and is dangerous with user input.",
        "cwe": "CWE-95",
    },
    {
        "id": "B104",
        "name": "hardcoded_bind_all",
        "pattern": r"['\"]0\.0\.0\.0['\"]",
        "severity": "MEDIUM",
        "message": "Binding to all interfaces (0.0.0.0) may expose the service unintentionally.",
        "cwe": "CWE-605",
    },
    {
        "id": "B105",
        "name": "hardcoded_password_string",
        "pattern": r"(?i)(password|passwd|pwd|secret|api_key|token)\s*=\s*['\"][^'\"]{4,}['\"]",
        "severity": "HIGH",
        "message": "Possible hardcoded password or secret detected. Store secrets in environment variables.",
        "cwe": "CWE-259",
    },
    {
        "id": "B106",
        "name": "hardcoded_password_funcarg",
        "pattern": r"(?i)(password|passwd|pwd|secret)\s*=\s*['\"][^'\"]+['\"]",
        "severity": "MEDIUM",
        "message": "Hardcoded password passed as function argument.",
        "cwe": "CWE-259",
    },
    {
        "id": "B201",
        "name": "flask_debug_true",
        "pattern": r"\.run\s*\(.*debug\s*=\s*True",
        "severity": "HIGH",
        "message": "Flask app running in debug mode. This enables the interactive debugger and can expose sensitive data.",
        "cwe": "CWE-94",
    },
    {
        "id": "B301",
        "name": "pickle_usage",
        "pattern": r"\bpickle\.loads?\s*\(",
        "severity": "HIGH",
        "message": "Use of pickle.load()/loads() detected. Deserializing untrusted data with pickle can lead to arbitrary code execution.",
        "cwe": "CWE-502",
    },
    {
        "id": "B302",
        "name": "marshal_usage",
        "pattern": r"\bmarshal\.loads?\s*\(",
        "severity": "HIGH",
        "message": "Use of marshal.load()/loads() detected. This is unsafe with untrusted data.",
        "cwe": "CWE-502",
    },
    {
        "id": "B303",
        "name": "md5_usage",
        "pattern": r"(?i)(md5|sha1)\s*\(",
        "severity": "MEDIUM",
        "message": "Use of weak hashing algorithm (MD5/SHA1) detected. Use SHA-256 or stronger.",
        "cwe": "CWE-327",
    },
    {
        "id": "B304",
        "name": "subprocess_usage",
        "pattern": r"\bsubprocess\.(call|run|Popen|check_output)\s*\(",
        "severity": "MEDIUM",
        "message": "Use of subprocess detected. Ensure input is sanitized to avoid command injection.",
        "cwe": "CWE-78",
    },
    {
        "id": "B305",
        "name": "shell_true",
        "pattern": r"shell\s*=\s*True",
        "severity": "HIGH",
        "message": "subprocess called with shell=True. This is vulnerable to shell injection attacks.",
        "cwe": "CWE-78",
    },
    {
        "id": "B306",
        "name": "os_system",
        "pattern": r"\bos\.system\s*\(",
        "severity": "HIGH",
        "message": "Use of os.system() detected. Prefer subprocess with proper argument handling.",
        "cwe": "CWE-78",
    },
    {
        "id": "B307",
        "name": "random_usage",
        "pattern": r"\brandom\.(random|randint|choice|randrange)\s*\(",
        "severity": "LOW",
        "message": "Use of pseudo-random generator detected. For security-sensitive operations, use the secrets module.",
        "cwe": "CWE-338",
    },
    {
        "id": "B308",
        "name": "yaml_load",
        "pattern": r"\byaml\.load\s*\(",
        "severity": "HIGH",
        "message": "Use of yaml.load() without Loader is unsafe. Use yaml.safe_load() instead.",
        "cwe": "CWE-20",
    },
    {
        "id": "B309",
        "name": "sql_injection",
        "pattern": r"(?i)(execute|executemany)\s*\(\s*[f'\"].*%(s|d)|execute\s*\(\s*f['\"]",
        "severity": "HIGH",
        "message": "Possible SQL injection via string formatting. Use parameterized queries instead.",
        "cwe": "CWE-89",
    },
    {
        "id": "B310",
        "name": "request_without_timeout",
        "pattern": r"\brequests\.(get|post|put|delete|patch|head)\s*\([^)]*\)",
        "severity": "LOW",
        "message": "HTTP request made without a timeout. This can cause the application to hang indefinitely.",
        "cwe": "CWE-400",
    },
]


# ---------------------------------------------------------------------------
# LAYER 2: SEMGREP-STYLE RULES (OWASP Top 10 focused)
# These focus on web-specific vulnerabilities from the OWASP Top 10 list:
# Injection, Broken Auth, XSS, Insecure Deserialization, etc.
# ---------------------------------------------------------------------------

SEMGREP_RULES = [
    {
        "id": "SG001",
        "name": "owasp-a01-path-traversal",
        "pattern": r"open\s*\(\s*.*\+|open\s*\(\s*f['\"]",
        "severity": "HIGH",
        "owasp": "A01:2021 - Broken Access Control",
        "message": "Potential path traversal vulnerability. User input may be used to construct file paths.",
        "cwe": "CWE-22",
    },
    {
        "id": "SG002",
        "name": "owasp-a02-hardcoded-token",
        "pattern": r"(?i)(bearer|token|jwt)\s*[=:]\s*['\"][A-Za-z0-9+/=._-]{20,}['\"]",
        "severity": "HIGH",
        "owasp": "A02:2021 - Cryptographic Failures",
        "message": "Hardcoded authentication token detected. Tokens must not be stored in source code.",
        "cwe": "CWE-798",
    },
    {
        "id": "SG003",
        "name": "owasp-a03-sqli",
        "pattern": r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*['\"\+].*(?:input|param|request|user|data)",
        "severity": "HIGH",
        "owasp": "A03:2021 - Injection",
        "message": "Potential SQL injection. SQL query appears to be built from user-controlled input.",
        "cwe": "CWE-89",
    },
    {
        "id": "SG004",
        "name": "owasp-a03-command-injection",
        "pattern": r"(?i)(os\.system|subprocess\.call|subprocess\.run|Popen)\s*\(.*(?:input|param|request|user|data|f['\"])",
        "severity": "HIGH",
        "owasp": "A03:2021 - Injection",
        "message": "Potential command injection. System command appears to use user-controlled input.",
        "cwe": "CWE-78",
    },
    {
        "id": "SG005",
        "name": "owasp-a03-xss",
        "pattern": r"(?i)(render|template|html)\s*\(.*(?:input|param|request|user|data)",
        "severity": "MEDIUM",
        "owasp": "A03:2021 - Injection (XSS)",
        "message": "Potential XSS vulnerability. User input may be rendered without sanitization.",
        "cwe": "CWE-79",
    },
    {
        "id": "SG006",
        "name": "owasp-a04-insecure-xml",
        "pattern": r"(?i)(xml\.etree|lxml|minidom|expat).*parse",
        "severity": "MEDIUM",
        "owasp": "A04:2021 - Insecure Design",
        "message": "XML parsing detected. Verify protection against XXE (XML External Entity) attacks.",
        "cwe": "CWE-611",
    },
    {
        "id": "SG007",
        "name": "owasp-a05-debug-mode",
        "pattern": r"(?i)(DEBUG\s*=\s*True|TESTING\s*=\s*True)",
        "severity": "MEDIUM",
        "owasp": "A05:2021 - Security Misconfiguration",
        "message": "Debug or testing mode enabled. Disable in production to prevent information leakage.",
        "cwe": "CWE-94",
    },
    {
        "id": "SG008",
        "name": "owasp-a07-weak-password-policy",
        "pattern": r"(?i)min_length\s*[=:]\s*[1-5][^0-9]",
        "severity": "MEDIUM",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "message": "Weak password minimum length (less than 6). Use at least 8-12 characters.",
        "cwe": "CWE-521",
    },
    {
        "id": "SG009",
        "name": "owasp-a08-insecure-deserialization",
        "pattern": r"(?i)(pickle|marshal|shelve)\.loads?\s*\(",
        "severity": "HIGH",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "message": "Insecure deserialization detected. Deserializing untrusted data can lead to RCE.",
        "cwe": "CWE-502",
    },
    {
        "id": "SG010",
        "name": "owasp-a09-sensitive-logging",
        "pattern": r"(?i)(log|print|logger)\s*\(.*(?:password|token|secret|key|credential)",
        "severity": "MEDIUM",
        "owasp": "A09:2021 - Security Logging and Monitoring Failures",
        "message": "Sensitive data may be written to logs. Avoid logging passwords, tokens, or secrets.",
        "cwe": "CWE-532",
    },
    {
        "id": "SG011",
        "name": "owasp-a10-ssrf",
        "pattern": r"(?i)(requests\.(get|post)|urllib|httpx)\s*\(.*(?:input|param|request|user|url|data)",
        "severity": "HIGH",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "message": "Potential SSRF vulnerability. HTTP request URL may be user-controlled.",
        "cwe": "CWE-918",
    },
]


# ---------------------------------------------------------------------------
# SCANNING FUNCTIONS
# ---------------------------------------------------------------------------

def run_bandit_scan(code: str) -> list:
    """
    Run Bandit-style rules against the submitted code.
    Scans line by line and returns a list of findings.
    """
    findings = []
    lines = code.split("\n")

    for rule in BANDIT_RULES:
        pattern = re.compile(rule["pattern"])
        for line_num, line in enumerate(lines, start=1):
            if pattern.search(line):
                findings.append({
                    "tool": "bandit",
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "message": rule["message"],
                    "cwe": rule["cwe"],
                    "line_number": line_num,
                    "line_content": line.strip(),
                })

    return findings


def run_semgrep_scan(code: str) -> list:
    """
    Run Semgrep-style OWASP Top 10 rules against the submitted code.
    Returns a list of findings with OWASP category labels.
    """
    findings = []
    lines = code.split("\n")

    for rule in SEMGREP_RULES:
        pattern = re.compile(rule["pattern"])
        for line_num, line in enumerate(lines, start=1):
            if pattern.search(line):
                findings.append({
                    "tool": "semgrep",
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "owasp_category": rule.get("owasp", "N/A"),
                    "message": rule["message"],
                    "cwe": rule["cwe"],
                    "line_number": line_num,
                    "line_content": line.strip(),
                })

    return findings


def deduplicate_findings(findings: list) -> list:
    """
    Remove duplicate findings where Bandit and Semgrep both flagged
    the same line for the same underlying issue (e.g., pickle).
    Keeps the first occurrence.
    """
    seen = set()
    unique = []
    for f in findings:
        key = (f["line_number"], f["cwe"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def build_gemini_prompt(code: str, findings: list, language: str) -> str:
    """
    Build a clear prompt for Gemini AI.
    Gives Gemini the code + all findings and asks it to:
    - Explain each issue in simple terms
    - Give a concrete fix for each
    - Give an overall risk summary
    """
    if not findings:
        return f"""
You are a security expert reviewing {language} code.
The automated scanners found no issues in the following code.
Please briefly confirm it looks safe and mention any best practices.

CODE:
{code[:3000]}
"""

    findings_text = ""
    for i, f in enumerate(findings, 1):
        findings_text += f"""
Issue {i}:
  Tool: {f['tool']}
  Rule: {f['rule_id']} - {f['rule_name']}
  Severity: {f['severity']}
  CWE: {f['cwe']}
  Line {f['line_number']}: {f['line_content']}
  Message: {f['message']}
"""

    return f"""
You are a security expert. Automated scanners found security issues in this {language} code.

For each issue below, provide:
1. A plain-English explanation of WHY it is dangerous
2. A concrete code fix or recommendation
3. The real-world attack scenario if exploited

Then provide an OVERALL RISK SUMMARY with a risk level: Low / Medium / High / Critical.

FINDINGS:
{findings_text}

CODE (first 3000 chars):
{code[:3000]}

Format your response as JSON with this structure:
{{
  "issue_explanations": [
    {{
      "issue_number": 1,
      "why_dangerous": "...",
      "how_to_fix": "...",
      "attack_scenario": "..."
    }}
  ],
  "overall_risk_level": "Low|Medium|High|Critical",
  "overall_summary": "..."
}}
Only return valid JSON, no markdown, no extra text.
"""


async def run_gemini_analysis(code: str, findings: list, language: str, gemini_api_key: str) -> dict:
    """
    Call Gemini API with the code and findings.
    Returns AI-generated explanations and fix suggestions.
    If API key is missing or call fails, returns a graceful fallback.
    """
    if not gemini_api_key:
        return {
            "available": False,
            "reason": "GEMINI_API_KEY not configured in environment secrets.",
            "issue_explanations": [],
            "overall_risk_level": "Unknown",
            "overall_summary": "Gemini AI analysis unavailable. Configure GEMINI_API_KEY secret in Cloudflare dashboard.",
        }

    prompt = build_gemini_prompt(code, findings, language)

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 2048,
        },
    }

    try:
        url = f"{GEMINI_API_URL}?key={gemini_api_key}"
        response = await fetch(
            url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps(payload),
        )
        response_text = await response.text()
        response_data = json.loads(response_text)

        # Extract text from Gemini response structure
        gemini_text = (
            response_data
            .get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
        )

        # Parse the JSON Gemini returned
        try:
            ai_result = json.loads(gemini_text)
            ai_result["available"] = True
            return ai_result
        except json.JSONDecodeError:
            # Gemini returned text instead of JSON — wrap it
            return {
                "available": True,
                "raw_response": gemini_text,
                "overall_risk_level": "Unknown",
                "overall_summary": gemini_text[:500],
                "issue_explanations": [],
            }

    except Exception as e:
        return {
            "available": False,
            "reason": f"Gemini API call failed: {str(e)}",
            "issue_explanations": [],
            "overall_risk_level": "Unknown",
            "overall_summary": "Gemini AI analysis failed due to an error.",
        }


def calculate_risk_score(findings: list) -> dict:
    """
    Calculate a numeric risk score from 0-100 based on findings.
    HIGH = 30 pts, MEDIUM = 10 pts, LOW = 3 pts. Capped at 100.
    """
    score = 0
    severity_weights = {"HIGH": 30, "MEDIUM": 10, "LOW": 3}

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        score += severity_weights.get(sev, 0)
        counts[sev] = counts.get(sev, 0) + 1

    score = min(score, 100)

    if score >= 70:
        level = "Critical"
    elif score >= 40:
        level = "High"
    elif score >= 15:
        level = "Medium"
    elif score > 0:
        level = "Low"
    else:
        level = "Clean"

    return {
        "score": score,
        "level": level,
        "high_count": counts["HIGH"],
        "medium_count": counts["MEDIUM"],
        "low_count": counts["LOW"],
        "total_issues": len(findings),
    }


# ---------------------------------------------------------------------------
# URL + REQUEST ROUTING (unchanged from original)
# ---------------------------------------------------------------------------

def parse_path(url):
    url_without_protocol = url.split("://", 1)[1] if "://" in url else url
    path_start = url_without_protocol.find("/")
    if path_start == -1:
        path = "/"
    else:
        path_with_query = url_without_protocol[path_start:]
        path = path_with_query.split("?")[0].split("#")[0]
        if not path.startswith("/"):
            path = "/" + path
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]
    return path


async def on_fetch(request, env):
    url = request.url
    method = request.method

    try:
        path = parse_path(url)
    except Exception as e:
        return create_error_response(f"Error parsing URL: {str(e)}", 500)

    if method == "OPTIONS":
        return handle_options(request)

    if path == "/" or path == "":
        if method in ("GET", "HEAD"):
            return handle_root(request)
        return create_method_not_allowed_response(path, ["GET", "HEAD"])
    elif path == "/health":
        if method in ("GET", "HEAD"):
            return handle_health(request)
        return create_method_not_allowed_response(path, ["GET", "HEAD"])
    elif path == "/api/review":
        if method == "POST":
            return await handle_review(request, env)
        return create_method_not_allowed_response(path, ["POST"])
    elif path == "/api/status":
        if method in ("GET", "HEAD"):
            return handle_status(request)
        return create_method_not_allowed_response(path, ["GET", "HEAD"])
    else:
        return create_error_response(f"Not Found: {path}", 404)


# ---------------------------------------------------------------------------
# ROUTE HANDLERS
# ---------------------------------------------------------------------------

def handle_options(request):
    headers = Headers.new()
    headers.set("Access-Control-Allow-Origin", "*")
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
    headers.set("Access-Control-Allow-Headers", "Content-Type")
    headers.set("Access-Control-Max-Age", "86400")
    return Response.new("", status=204, headers=headers)


def handle_root(request):
    response_data = {
        "service": "Toasty AI Code Reviewer",
        "version": "1.1.0",
        "description": "Backend API for OWASP BLT's AI-powered code review service",
        "security_scanning": {
            "bandit_rules": len(BANDIT_RULES),
            "semgrep_rules": len(SEMGREP_RULES),
            "gemini_ai": "enabled when GEMINI_API_KEY is configured",
        },
        "endpoints": {
            "/": "Service information",
            "/health": "Health check endpoint",
            "/api/review": "POST - Submit code for security review",
            "/api/status": "GET - Check service status",
        },
    }
    return create_json_response(response_data, 200)


def handle_health(request):
    health_data = {
        "status": "healthy",
        "service": "toasty-backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return create_json_response(health_data, 200)


async def handle_review(request, env):
    """
    Main security review endpoint.
    Accepts code, runs Bandit + Semgrep pattern scans,
    then sends findings to Gemini for AI-powered explanation.
    """
    try:
        # --- Size check ---
        content_length_header = request.headers.get("Content-Length")
        if content_length_header:
            try:
                if int(content_length_header) > MAX_BODY_SIZE:
                    return create_error_response(
                        f"Request body too large. Max is {MAX_BODY_SIZE} bytes.", 413
                    )
            except ValueError:
                pass

        body = await request.text()
        if len(body) > MAX_BODY_SIZE:
            return create_error_response("Request body too large.", 413)
        if not body:
            return create_error_response("Request body is required.", 400)

        # --- Parse JSON ---
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return create_error_response("Invalid JSON in request body.", 400)

        # --- Validate fields ---
        if "code" not in data:
            return create_error_response("Missing required field: 'code'", 400)
        code = data.get("code")
        if not isinstance(code, str) or not code.strip():
            return create_error_response("Field 'code' must be a non-empty string.", 400)

        language = data.get("language", "python")
        context = data.get("context", "")

        # --- LAYER 1: Bandit-style scan ---
        bandit_findings = run_bandit_scan(code)

        # --- LAYER 2: Semgrep-style scan ---
        semgrep_findings = run_semgrep_scan(code)

        # --- Combine and deduplicate ---
        all_findings = deduplicate_findings(bandit_findings + semgrep_findings)

        # --- Risk score ---
        risk = calculate_risk_score(all_findings)

        # --- LAYER 3: Gemini AI analysis ---
        gemini_api_key = getattr(env, "GEMINI_API_KEY", None)
        ai_analysis = await run_gemini_analysis(code, all_findings, language, gemini_api_key)

        # --- Build final response ---
        review_result = {
            "status": "success",
            "analysis": {
                "language": language,
                "context": context,
                "lines_of_code": len(code.split("\n")),
                "risk": risk,
                "findings": {
                    "bandit": bandit_findings,
                    "semgrep": semgrep_findings,
                    "total_unique": len(all_findings),
                    "all": all_findings,
                },
                "ai_analysis": ai_analysis,
            },
            "metadata": {
                "processed_at": datetime.now(timezone.utc).isoformat(),
                "worker_version": "1.1.0",
                "scanner_versions": {
                    "bandit_rules": len(BANDIT_RULES),
                    "semgrep_rules": len(SEMGREP_RULES),
                    "gemini_model": "gemini-2.0-flash",
                },
            },
        }

        return create_json_response(review_result, 200)

    except Exception as e:
        return create_error_response(f"Error processing review: {str(e)}", 500)


def handle_status(request):
    status_data = {
        "service": "toasty-backend",
        "status": "operational",
        "version": "1.1.0",
        "features": {
            "bandit_security_scan": "available",
            "semgrep_owasp_scan": "available",
            "gemini_ai_analysis": "available when GEMINI_API_KEY configured",
            "health_check": "available",
            "status_monitoring": "available",
        },
        "uptime": "available",
    }
    return create_json_response(status_data, 200)


# ---------------------------------------------------------------------------
# RESPONSE HELPERS (unchanged from original)
# ---------------------------------------------------------------------------

def create_json_response(data, status_code=200):
    headers = Headers.new()
    headers.set("Content-Type", "application/json")
    headers.set("Access-Control-Allow-Origin", "*")
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
    headers.set("Access-Control-Allow-Headers", "Content-Type")
    return Response.new(json.dumps(data), status=status_code, headers=headers)


def create_error_response(message, status_code=500):
    return create_json_response({"error": message, "status": status_code}, status_code)


def create_method_not_allowed_response(path, allowed_methods):
    message = f"Method Not Allowed for {path}. Allowed: {', '.join(allowed_methods)}"
    headers = Headers.new()
    headers.set("Content-Type", "application/json")
    headers.set("Access-Control-Allow-Origin", "*")
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
    headers.set("Access-Control-Allow-Headers", "Content-Type")
    headers.set("Allow", ", ".join(allowed_methods))
    error_data = {"error": "Method Not Allowed", "message": message, "status": 405}
    return Response.new(json.dumps(error_data), status=405, headers=headers)
