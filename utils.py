from __future__ import annotations

from html import escape
from typing import Iterable
from urllib.parse import parse_qsl, urlparse


COMMON_QUERY_PARAMS = [
    "id",
    "q",
    "query",
    "search",
    "page",
    "next",
    "redirect",
    "url",
    "return",
    "file",
]

URL_LIKE_PARAMS = {
    "callback",
    "continue",
    "dest",
    "destination",
    "image",
    "link",
    "next",
    "path",
    "redirect",
    "return",
    "return_to",
    "target",
    "uri",
    "url",
}

SENSITIVE_PATH_RULES = {
    "/.env": {
        "severity": "high",
        "vuln_type": "InfoDisclosure",
        "title": "Exposed environment file",
        "reasoning": "The application appears to expose a runtime environment file over HTTP.",
    },
    "/.git/config": {
        "severity": "high",
        "vuln_type": "InfoDisclosure",
        "title": "Exposed Git metadata",
        "reasoning": "The Git configuration appears reachable over HTTP and can leak repository details.",
    },
    "/config.php": {
        "severity": "high",
        "vuln_type": "InfoDisclosure",
        "title": "Exposed configuration file",
        "reasoning": "A configuration file appears directly accessible over HTTP.",
    },
    "/backup": {
        "severity": "medium",
        "vuln_type": "Misconfiguration",
        "title": "Potential backup artifact exposed",
        "reasoning": "A backup location appears reachable and may expose sensitive content.",
    },
    "/phpmyadmin": {
        "severity": "medium",
        "vuln_type": "Misconfiguration",
        "title": "Administrative console exposed",
        "reasoning": "An administrative surface is exposed and may be reachable from the public internet.",
    },
    "/server-status": {
        "severity": "medium",
        "vuln_type": "InfoDisclosure",
        "title": "Server status page exposed",
        "reasoning": "The web server status page is exposed and may leak operational information.",
    },
    "/actuator/env": {
        "severity": "high",
        "vuln_type": "InfoDisclosure",
        "title": "Spring actuator environment exposed",
        "reasoning": "The Spring Boot actuator environment endpoint appears accessible and may leak secrets.",
    },
    "/actuator/health": {
        "severity": "low",
        "vuln_type": "InfoDisclosure",
        "title": "Spring actuator health endpoint exposed",
        "reasoning": "The actuator health endpoint is exposed and leaks deployment metadata.",
    },
    "/swagger": {
        "severity": "info",
        "vuln_type": "Misconfiguration",
        "title": "Swagger endpoint exposed",
        "reasoning": "Interactive API documentation is publicly reachable.",
    },
    "/swagger-ui.html": {
        "severity": "info",
        "vuln_type": "Misconfiguration",
        "title": "Swagger UI exposed",
        "reasoning": "Interactive API documentation is publicly reachable.",
    },
    "/openapi.json": {
        "severity": "info",
        "vuln_type": "InfoDisclosure",
        "title": "OpenAPI specification exposed",
        "reasoning": "The API schema appears publicly accessible and can expand attack surface discovery.",
    },
}


def normalize_target(target: str, default_scheme: str = "https") -> str:
    raw = (target or "").strip()
    if not raw:
        raise ValueError("Target is required.")

    if "://" not in raw:
        raw = f"{default_scheme}://{raw}"

    parsed = urlparse(raw)
    scheme = parsed.scheme or default_scheme
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")

    if not netloc:
        raise ValueError(f"Could not parse target: {target}")

    return f"{scheme}://{netloc}{path}"


def extract_host(target: str) -> str:
    return urlparse(normalize_target(target)).netloc


def unique_preserve_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item and item not in seen:
            ordered.append(item)
            seen.add(item)
    return ordered


def build_candidate_hosts(target: str, subdomains: list[str] | None, max_hosts: int) -> list[str]:
    base = normalize_target(target)
    parsed = urlparse(base)
    hosts = [base]

    for subdomain in subdomains or []:
        sub = subdomain.strip().lower()
        if not sub or sub == parsed.netloc:
            continue
        hosts.append(f"{parsed.scheme}://{sub}")

    return unique_preserve_order(hosts)[: max(1, max_hosts)]


def extract_query_params(url: str) -> list[str]:
    parsed = urlparse(url)
    return [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if key]


def infer_params_from_path(url: str) -> list[str]:
    path = urlparse(url).path.lower()
    inferred: list[str] = []

    if "search" in path:
        inferred.extend(["q", "query", "search"])
    if "login" in path or "auth" in path:
        inferred.extend(["next", "return", "redirect"])
    if "product" in path or "user" in path or "api" in path:
        inferred.extend(["id", "page"])
    if "redirect" in path or "callback" in path or "proxy" in path:
        inferred.extend(["url", "next", "redirect"])

    return unique_preserve_order(inferred)


def build_candidate_params(url: str) -> list[str]:
    return unique_preserve_order(
        extract_query_params(url) + infer_params_from_path(url) + COMMON_QUERY_PARAMS
    )


def is_url_like_param(name: str) -> bool:
    normalized = (name or "").strip().lower()
    return normalized in URL_LIKE_PARAMS or "url" in normalized or "redirect" in normalized


def escape_reflection(text: str) -> str:
    return escape(text, quote=True)


def safe_slug(value: str) -> str:
    lowered = value.lower()
    return "".join(char if char.isalnum() else "_" for char in lowered).strip("_")
