import asyncio
import time
import uuid
from urllib.parse import urlparse

import httpx

from config import Settings
from utils import build_candidate_params, is_url_like_param, normalize_target

# ── XSS probes (unique canary per run) ───────────────────────────────────────

def _xss_probes() -> list[dict]:
    canary = uuid.uuid4().hex[:12]
    return [
        {
            "payload": f"<script>alert('{canary}')</script>",
            "canary": canary,
            "description": "Basic script-tag injection",
        },
        {
            "payload": f'"><img src=x onerror=alert(\'{canary}\')>',
            "canary": canary,
            "description": "Attribute-breakout img onerror",
        },
    ]


# ── SQLi error signatures (specific, not generic) ────────────────────────────

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql_",
    "mysql_fetch_array()",
    "pg_query(): query failed",
    "supplied argument is not a valid postgresql",
    "ora-00907",
    "ora-00933",
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "microsoft ole db provider for sql server",
    "sqlite3::query",
    "sqlstate[",
    "jdbc driver",
]

# ── Open redirect canary ──────────────────────────────────────────────────────

REDIRECT_CANARY = "phantomaitest.invalid"
REDIRECT_PAYLOADS = [
    f"https://{REDIRECT_CANARY}",
    f"//{REDIRECT_CANARY}",
    f"https://{REDIRECT_CANARY}/%2F..",
]

# ── SSRF payloads + confirmed content markers ─────────────────────────────────

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",          # AWS
    "http://[::ffff:169.254.169.254]/latest/meta-data/", # AWS IPv6-mapped bypass
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
]
SSRF_CONFIRMED_MARKERS = [
    # AWS
    "ami-id",
    "instance-id",
    "instance-type",
    "local-hostname",
    "local-ipv4",
    # GCP
    "computemetadata",
    "project-id",
    "service-accounts",
    # Azure
    "azureenvironment",
    "subscriptionid",
    "resourcegroupname",
]

DEFAULT_TEST_CASES = [
    ("{base}/search", "q", ["xss", "sqli"]),
    ("{base}/", "redirect", ["redirect"]),
    ("{base}/", "url", ["ssrf", "redirect"]),
    ("{base}/api/v1/users", "id", ["sqli"]),
    ("{base}/login", "next", ["redirect"]),
    ("{base}/products", "id", ["sqli", "xss"]),
]


# ── XSS confirmation ──────────────────────────────────────────────────────────

async def _confirm_xss(client, base_url, param, body_sample_size):
    """
    Confirm XSS by:
    1. Per-request unique canary — cannot be a pre-existing page string.
    2. Baseline check — canary must NOT appear before injection.
    3. Unescaped canary + executable context must both be present after injection.
    """
    for probe in _xss_probes():
        payload = probe["payload"]
        canary = probe["canary"]
        try:
            baseline = await client.get(base_url)
            if canary in baseline.text:
                continue  # canary already in page — not our injection

            resp = await client.get(base_url, params={param: payload})
            body = resp.text[:body_sample_size]

            if canary in body and any(
                marker in body.lower()
                for marker in [
                    f"alert('{canary}')",
                    f"onerror=alert('{canary}')",
                ]
            ):
                return {
                    "type": "XSS",
                    "severity": "medium",
                    "url": base_url,
                    "param": param,
                    "payload": payload,
                    "canary": canary,
                    "status": resp.status_code,
                    "reasoning": (
                        f"Canary '{canary}' reflected unescaped in an executable "
                        "context; absent in baseline."
                    ),
                    "response_snippet": body[:500],
                }
        except Exception:
            continue
    return None


# ── SQLi confirmation ─────────────────────────────────────────────────────────

async def _confirm_sqli(client, base_url, param, body_sample_size):
    """
    Confirm SQLi by:
    1. Record baseline response for a benign value.
    2. Inject payload; look for DB error signatures.
    3. Signature must be absent in baseline to exclude pre-existing error pages.
    """
    sqli_payloads = ["'", '"', "' OR '1'='1'--", "1 AND 1=2--"]
    try:
        baseline_resp = await client.get(base_url, params={param: "1"})
        baseline_body = baseline_resp.text[:body_sample_size].lower()
    except Exception:
        return None

    for payload in sqli_payloads:
        try:
            resp = await client.get(base_url, params={param: payload})
            body = resp.text[:body_sample_size].lower()
            for sig in SQLI_ERROR_SIGNATURES:
                if sig in body and sig not in baseline_body:
                    return {
                        "type": "SQLi",
                        "severity": "high",
                        "url": base_url,
                        "param": param,
                        "payload": payload,
                        "status": resp.status_code,
                        "db_error": sig,
                        "reasoning": (
                            f"DB error '{sig}' appeared after injection but not in baseline."
                        ),
                        "response_snippet": resp.text[:500],
                    }
        except Exception:
            continue
    return None


# ── Open redirect confirmation ────────────────────────────────────────────────

async def _confirm_redirect(client, base_url, param):
    """
    Confirm open redirect by:
    1. Sending our unique canary domain as redirect target.
    2. Location header must contain the exact canary.
    3. Cross-check: benign value must NOT produce same redirect.
    """
    for payload in REDIRECT_PAYLOADS:
        try:
            resp = await client.get(base_url, params={param: payload})
            location = resp.headers.get("location", "").lower()

            if resp.status_code in (301, 302, 303, 307, 308) and REDIRECT_CANARY in location:
                benign = await client.get(base_url, params={param: "home"})
                benign_loc = benign.headers.get("location", "").lower()
                if REDIRECT_CANARY not in benign_loc:
                    return {
                        "type": "OpenRedirect",
                        "severity": "medium",
                        "url": base_url,
                        "param": param,
                        "payload": payload,
                        "redirect_to": resp.headers.get("location"),
                        "reasoning": (
                            f"Redirected to attacker-supplied domain '{REDIRECT_CANARY}'; "
                            "benign value did not trigger same redirect."
                        ),
                    }
        except Exception:
            continue
    return None


# ── SSRF confirmation ─────────────────────────────────────────────────────────

async def _confirm_ssrf(client, base_url, param, body_sample_size):
    """
    Confirm SSRF by:
    1. Baseline with safe external URL.
    2. Inject AWS metadata endpoint.
    3. Actual metadata content (ami-id, instance-id, etc.) must appear
       in response but not in baseline.
    """
    try:
        baseline = await client.get(base_url, params={param: "https://example.com"})
        baseline_body = baseline.text[:body_sample_size].lower()
    except Exception:
        return None

    for payload in SSRF_PAYLOADS:
        try:
            resp = await client.get(base_url, params={param: payload})
            body = resp.text[:body_sample_size].lower()
            for marker in SSRF_CONFIRMED_MARKERS:
                if marker in body and marker not in baseline_body:
                    return {
                        "type": "SSRF",
                        "severity": "critical",
                        "url": base_url,
                        "param": param,
                        "payload": payload,
                        "marker_found": marker,
                        "status": resp.status_code,
                        "reasoning": (
                            f"AWS metadata marker '{marker}' in response after SSRF payload; "
                            "absent in baseline."
                        ),
                        "response_snippet": resp.text[:500],
                    }
        except Exception:
            continue
    return None


# ── Build test cases ──────────────────────────────────────────────────────────

def _build_test_cases(base, interesting):
    cases = []
    for template, param, types in DEFAULT_TEST_CASES:
        cases.append({"url": template.format(base=base), "param": param, "types": types})

    for endpoint in interesting or []:
        url = endpoint.get("url")
        if not url:
            continue
        path = urlparse(url).path.lower()
        params = build_candidate_params(url)
        for param in params[:5]:
            types = ["xss", "sqli"]
            if is_url_like_param(param):
                types = ["redirect", "ssrf"]
            elif "login" in path and param in {"next", "return", "redirect"}:
                types = ["redirect"]
            cases.append({"url": url, "param": param, "types": types})

    unique, seen = [], set()
    for case in cases:
        key = (case["url"], case["param"], tuple(sorted(case["types"])))
        if key not in seen:
            unique.append(case)
            seen.add(key)
    return unique[:40]


# ── Main entry ────────────────────────────────────────────────────────────────

async def run_fuzz(target: str, interesting: list[dict], settings: Settings) -> dict:
    base = normalize_target(target)
    test_cases = _build_test_cases(base, interesting)
    tasks = []

    async with httpx.AsyncClient(
        timeout=settings.scan.timeout,
        headers={"User-Agent": settings.scan.user_agent},
        verify=settings.scan.verify_tls,
        proxy=settings.proxy.url if settings.proxy.enabled else None,
        follow_redirects=False,
        limits=httpx.Limits(max_connections=settings.scan.concurrency),
    ) as client:
        for case in test_cases:
            url, param, types = case["url"], case["param"], case["types"]
            if "xss" in types:
                tasks.append(_confirm_xss(client, url, param, settings.scan.body_sample_size))
            if "sqli" in types:
                tasks.append(_confirm_sqli(client, url, param, settings.scan.body_sample_size))
            if "redirect" in types:
                tasks.append(_confirm_redirect(client, url, param))
            if "ssrf" in types:
                tasks.append(_confirm_ssrf(client, url, param, settings.scan.body_sample_size))

        results = await asyncio.gather(*tasks)

    confirmed, seen_hits = [], set()
    for hit in results:
        if hit is None:
            continue
        key = (hit["type"], hit["url"], hit.get("param"))
        if key not in seen_hits:
            confirmed.append(hit)
            seen_hits.add(key)

    return {"target": base, "hits": confirmed, "total": len(confirmed), "tested_cases": len(test_cases)}
