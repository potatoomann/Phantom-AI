"""
owasp_checks.py
OWASP Top 10 2021 + 2025 vulnerability definitions and test payloads.
Every check is tagged with its OWASP category so findings can be reported
with proper references.
"""

# ---------------------------------------------------------------------------
# OWASP Top 10 - 2021
# ---------------------------------------------------------------------------
OWASP_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging & Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# ---------------------------------------------------------------------------
# OWASP Top 10 - 2025 (Web Application)
# ---------------------------------------------------------------------------
OWASP_2025 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging & Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# ---------------------------------------------------------------------------
# Check definitions
# Each check has:
#   id          - unique identifier
#   name        - human-readable name
#   owasp_2021  - OWASP 2021 category code
#   owasp_2025  - OWASP 2025 category code
#   severity    - critical / high / medium / low / info
#   payloads    - list of injection strings (None if passive only)
#   passive     - True if this check only looks at the request/response
#   indicators  - strings that indicate a hit in the response body
#   url_patterns - URL patterns that trigger this check
# ---------------------------------------------------------------------------
CHECKS = [

    # -----------------------------------------------------------------------
    # A03 - Injection
    # -----------------------------------------------------------------------
    {
        "id": "sqli_error",
        "name": "SQL Injection (Error-Based)",
        "owasp_2021": "A03",
        "owasp_2025": "A03",
        "severity": "critical",
        "passive": False,
        "payloads": ["'", "''", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1"],
        "indicators": [
            "sql syntax", "mysql_fetch", "ora-", "pg_query", "sqlite",
            "unclosed quotation", "you have an error in your sql",
            "warning: mysql", "jdbc", "odbc driver",
        ],
        "url_patterns": ["="],
    },
    {
        "id": "sqli_blind",
        "name": "SQL Injection (Time-Based Blind)",
        "owasp_2021": "A03",
        "owasp_2025": "A03",
        "severity": "critical",
        "passive": False,
        "payloads": [
            "' AND SLEEP(5)--",
            "' AND pg_sleep(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
        ],
        "indicators": [],   # Detected by response time > 4s
        "url_patterns": ["="],
        "time_based": True,
        "time_threshold": 4.0,
    },
    {
        "id": "xss_reflected",
        "name": "Reflected XSS",
        "owasp_2021": "A03",
        "owasp_2025": "A03",
        "severity": "high",
        "passive": False,
        "payloads": [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
        ],
        "indicators": ["<script>alert(1)</script>", "onerror=alert(1)", "onload=alert(1)"],
        "url_patterns": ["search", "q=", "query=", "input=", "name=", "msg=", "redirect="],
    },
    {
        "id": "ssti",
        "name": "Server-Side Template Injection (SSTI)",
        "owasp_2021": "A03",
        "owasp_2025": "A03",
        "severity": "critical",
        "passive": False,
        "payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "${7*7}"],
        "indicators": ["49"],  # 7*7 = 49
        "url_patterns": ["="],
    },
    {
        "id": "cmd_injection",
        "name": "OS Command Injection",
        "owasp_2021": "A03",
        "owasp_2025": "A03",
        "severity": "critical",
        "passive": False,
        "payloads": [
            "; ls",
            "| id",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "| whoami",
        ],
        "indicators": ["root:", "uid=", "/bin/", "www-data", "daemon"],
        "url_patterns": ["cmd=", "exec=", "command=", "run=", "shell="],
    },
    {
        "id": "xxe",
        "name": "XML External Entity (XXE)",
        "owasp_2021": "A03",
        "owasp_2025": "A03",
        "severity": "critical",
        "passive": False,
        "payloads": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        ],
        "indicators": ["root:", "daemon:", "/bin/"],
        "url_patterns": ["xml", "soap", "wsdl"],
    },
    {
        "id": "ldap_injection",
        "name": "LDAP Injection",
        "owasp_2021": "A03",
        "owasp_2025": "A03",
        "severity": "high",
        "passive": False,
        "payloads": ["*)(uid=*))(|(uid=*", "admin)(&)", "*|%26"],
        "indicators": ["ldap", "invalid dn", "no such object"],
        "url_patterns": ["user=", "uid=", "login="],
    },

    # -----------------------------------------------------------------------
    # A01 - Broken Access Control
    # -----------------------------------------------------------------------
    {
        "id": "idor",
        "name": "Insecure Direct Object Reference (IDOR)",
        "owasp_2021": "A01",
        "owasp_2025": "A01",
        "severity": "high",
        "passive": False,
        "payloads": ["0", "1", "2", "9999", "admin", "../admin"],
        "indicators": [],  # Detected by status 200 on different IDs
        "url_patterns": ["/user/", "/account/", "/order/", "/profile/", "/id="],
        "idor_check": True,
    },
    {
        "id": "path_traversal",
        "name": "Path Traversal",
        "owasp_2021": "A01",
        "owasp_2025": "A01",
        "severity": "high",
        "passive": False,
        "payloads": [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//etc/passwd",
        ],
        "indicators": ["root:", "daemon:", "/bin/bash"],
        "url_patterns": ["file=", "path=", "load=", "read=", "include=", "page="],
    },
    {
        "id": "sensitive_files_exposure",
        "name": "Sensitive File Exposure (Secrets/Git)",
        "owasp_2021": "A05",
        "owasp_2025": "A01",
        "severity": "high",
        "passive": False,
        "payloads": [
            ".env", ".git/config", "config.php", "wp-config.php", 
            "backup.sql", ".htaccess", "composer.json", "package.json",
            ".aws/credentials", ".docker/config.json", "id_rsa", ".ssh/id_rsa"
        ],
        "indicators": [
            "DB_PASSWORD", "DB_USER", "[core]", "repositoryformatversion",
            "AWS_SECRET_ACCESS_KEY", "dependencies", "RewriteEngine",
            "BEGIN RSA PRIVATE KEY", "auths"
        ],
        "url_patterns": ["/"],
    },
    {
        "id": "forced_browsing",
        "name": "Forced Browsing / Sensitive Endpoints",
        "owasp_2021": "A01",
        "owasp_2025": "A01",
        "severity": "medium",
        "passive": True,
        "payloads": None,
        "indicators": [],
        "sensitive_paths": [
            "/admin", "/administrator", "/admin.php", "/wp-admin",
            "/.env", "/config", "/backup", "/api/v1/users",
            "/api/admin", "/debug", "/actuator", "/metrics",
            "/swagger", "/api-docs", "/.git", "/phpinfo.php",
        ],
    },

    # -----------------------------------------------------------------------
    # A02 - Cryptographic Failures
    # -----------------------------------------------------------------------
    {
        "id": "sensitive_data_exposure",
        "name": "Sensitive Data in Response",
        "owasp_2021": "A02",
        "owasp_2025": "A02",
        "severity": "high",
        "passive": True,
        "payloads": None,
        "indicators": [
            "password", "secret", "api_key", "apikey", "private_key",
            "credit_card", "ssn", "social_security", "access_token",
            "BEGIN RSA PRIVATE KEY",
        ],
    },
    {
        "id": "http_used",
        "name": "Sensitive Data Sent Over HTTP (No TLS)",
        "owasp_2021": "A02",
        "owasp_2025": "A02",
        "severity": "medium",
        "passive": True,
        "payloads": None,
        "indicators": [],
        "http_check": True,
    },

    # -----------------------------------------------------------------------
    # A05 - Security Misconfiguration
    # -----------------------------------------------------------------------
    {
        "id": "debug_info",
        "name": "Debug / Stack Trace Exposed",
        "owasp_2021": "A05",
        "owasp_2025": "A05",
        "severity": "medium",
        "passive": True,
        "payloads": None,
        "indicators": [
            "traceback", "stack trace", "debug mode", "exception in thread",
            "syntaxerror", "uncaught exception", "at System.",
        ],
    },
    {
        "id": "missing_security_headers",
        "name": "Missing Security Headers",
        "owasp_2021": "A05",
        "owasp_2025": "A05",
        "severity": "low",
        "passive": True,
        "payloads": None,
        "indicators": [],
        "header_check": True,
        "required_headers": [
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
        ],
    },
    {
        "id": "cors_misconfiguration",
        "name": "CORS Misconfiguration",
        "owasp_2021": "A05",
        "owasp_2025": "A05",
        "severity": "high",
        "passive": True,
        "payloads": None,
        "indicators": [],
        "cors_check": True,
    },

    # -----------------------------------------------------------------------
    # A07 - Authentication Failures
    # -----------------------------------------------------------------------
    {
        "id": "weak_credentials",
        "name": "Weak/Default Credentials",
        "owasp_2021": "A07",
        "owasp_2025": "A07",
        "severity": "critical",
        "passive": False,
        "payloads": None,
        "indicators": [],
        "auth_check": True,
        "url_patterns": ["login", "signin", "auth", "authenticate"],
        "creds": [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("root", "root"), ("test", "test"),
        ],
    },
    {
        "id": "jwt_none_alg",
        "name": "JWT None Algorithm Attack",
        "owasp_2021": "A07",
        "owasp_2025": "A07",
        "severity": "critical",
        "passive": True,
        "payloads": None,
        "indicators": [],
        "jwt_check": True,
    },

    # -----------------------------------------------------------------------
    # A10 - SSRF
    # -----------------------------------------------------------------------
    {
        "id": "ssrf",
        "name": "Server-Side Request Forgery (SSRF)",
        "owasp_2021": "A10",
        "owasp_2025": "A10",
        "severity": "high",
        "passive": False,
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost/admin",
            "http://127.0.0.1:22",
            "http://[::1]/",
            "file:///etc/passwd",
        ],
        "indicators": ["ami-id", "instance-id", "root:", "ssh-", "OpenSSH"],
        "url_patterns": ["url=", "uri=", "redirect=", "proxy=", "fetch=", "load="],
    },
]
