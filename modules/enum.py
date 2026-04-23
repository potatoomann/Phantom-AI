import asyncio
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from config import Settings
from utils import SENSITIVE_PATH_RULES, build_candidate_hosts, unique_preserve_order

COMMON_PATHS = [
    "/",
    "/admin",
    "/login",
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/swagger",
    "/swagger-ui.html",
    "/openapi.json",
    "/.env",
    "/.git/config",
    "/robots.txt",
    "/sitemap.xml",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/config.php",
    "/backup",
    "/uploads",
    "/static",
    "/assets",
    "/js/app.js",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/console",
    "/debug",
    "/_debug",
    "/server-status",
]


async def probe_url(client: httpx.AsyncClient, url: str, body_sample_size: int) -> Optional[dict]:
    try:
        resp = await client.get(url)
        body = resp.text[:body_sample_size]
        return {
            "url": url,
            "status": resp.status_code,
            "length": len(resp.content),
            "server": resp.headers.get("server", ""),
            "content_type": resp.headers.get("content-type", ""),
            "x_powered_by": resp.headers.get("x-powered-by", ""),
            "location": resp.headers.get("location", ""),
            "sample": body,
        }
    except Exception:
        return None


async def run_enum(target: str, subdomains: list[str], settings: Settings) -> dict:
    base_hosts = build_candidate_hosts(target, subdomains, settings.scan.max_hosts)
    probe_urls = _build_probe_urls(base_hosts, settings.scan.max_endpoints)
    endpoints = []
    interesting = []

    async with httpx.AsyncClient(
        timeout=settings.scan.timeout,
        headers={"User-Agent": settings.scan.user_agent},
        verify=settings.scan.verify_tls,
        proxy=settings.proxy.url if settings.proxy.enabled else None,
        follow_redirects=settings.scan.follow_redirects,
        limits=httpx.Limits(max_connections=settings.scan.concurrency),
    ) as client:
        tasks = [probe_url(client, url, settings.scan.body_sample_size) for url in probe_urls]
        results = await asyncio.gather(*tasks)

    for result in results:
        if result is None:
            continue
        endpoints.append(result)
        status = result["status"]
        if status in (200, 201, 204, 301, 302, 401, 403, 500):
            interesting.append(result)

    tech_stack = _detect_tech(endpoints)
    issues = _detect_issues(interesting)

    return {
        "target": target,
        "hosts": base_hosts,
        "endpoints": endpoints,
        "interesting": interesting,
        "issues": issues,
        "tech_stack": tech_stack,
    }


def _detect_tech(endpoints: list) -> list:
    tech = set()
    for endpoint in endpoints:
        server = endpoint.get("server", "").lower()
        powered = endpoint.get("x_powered_by", "").lower()
        content_type = endpoint.get("content_type", "").lower()
        url = endpoint.get("url", "").lower()

        if "nginx" in server:
            tech.add("Nginx")
        if "apache" in server:
            tech.add("Apache")
        if "php" in powered or ".php" in url:
            tech.add("PHP")
        if "asp.net" in powered:
            tech.add("ASP.NET")
        if "express" in powered:
            tech.add("Node.js/Express")
        if "graphql" in url or "graphql" in content_type:
            tech.add("GraphQL")
        if "wp-" in url or "wordpress" in url:
            tech.add("WordPress")

    return sorted(tech)


def _build_probe_urls(hosts: list[str], max_endpoints: int) -> list[str]:
    if not hosts:
        return []

    primary = hosts[0]
    urls = [urljoin(f"{primary}/", path.lstrip("/")) for path in COMMON_PATHS]

    for host in hosts[1:]:
        urls.extend(
            [
                urljoin(f"{host}/", path.lstrip("/"))
                for path in ("/", "/robots.txt", "/.well-known/security.txt")
            ]
        )

    return unique_preserve_order(urls)[:max_endpoints]


def _detect_issues(endpoints: list[dict]) -> list[dict]:
    issues = []
    for endpoint in endpoints:
        path = urlparse(endpoint["url"]).path or "/"
        rule = SENSITIVE_PATH_RULES.get(path)
        if not rule or endpoint["status"] != 200:
            continue

        issues.append(
            {
                "type": rule["vuln_type"],
                "vuln_type": rule["vuln_type"],
                "severity": rule["severity"],
                "confidence": 0.92,
                "url": endpoint["url"],
                "title": rule["title"],
                "reasoning": rule["reasoning"],
                "evidence": {
                    "status": endpoint["status"],
                    "content_type": endpoint.get("content_type", ""),
                },
            }
        )

    return issues
