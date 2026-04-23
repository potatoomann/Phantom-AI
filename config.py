from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


DEFAULT_MODEL = "claude-sonnet-4-6"


@dataclass
class AISettings:
    model: str = DEFAULT_MODEL
    max_tokens: int = 4096


@dataclass
class ScanSettings:
    timeout: float = 10.0
    rate_limit: int = 20
    concurrency: int = 12
    max_subdomains: int = 200
    max_hosts: int = 25
    max_endpoints: int = 120
    max_ai_iterations: int = 5
    user_agent: str = "Mozilla/5.0 (compatible; PhantomAI/1.0)"
    verify_tls: bool = True
    follow_redirects: bool = False
    body_sample_size: int = 4096


@dataclass
class ProxySettings:
    enabled: bool = False
    url: str = ""


@dataclass
class OutputSettings:
    report_dir: str = "reports"
    log_level: str = "info"


@dataclass
class Settings:
    anthropic_api_key: str = ""
    gemini_api_key: str = ""
    ai: AISettings = field(default_factory=AISettings)
    scan: ScanSettings = field(default_factory=ScanSettings)
    proxy: ProxySettings = field(default_factory=ProxySettings)
    output: OutputSettings = field(default_factory=OutputSettings)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _defaults_dict() -> dict[str, Any]:
    defaults = Settings()
    return {
        "anthropic_api_key": defaults.anthropic_api_key,
        "gemini_api_key": defaults.gemini_api_key,
        "ai": {
            "model": defaults.ai.model,
            "max_tokens": defaults.ai.max_tokens,
        },
        "scan": {
            "timeout": defaults.scan.timeout,
            "rate_limit": defaults.scan.rate_limit,
            "concurrency": defaults.scan.concurrency,
            "max_subdomains": defaults.scan.max_subdomains,
            "max_hosts": defaults.scan.max_hosts,
            "max_endpoints": defaults.scan.max_endpoints,
            "max_ai_iterations": defaults.scan.max_ai_iterations,
            "user_agent": defaults.scan.user_agent,
            "verify_tls": defaults.scan.verify_tls,
            "follow_redirects": defaults.scan.follow_redirects,
            "body_sample_size": defaults.scan.body_sample_size,
        },
        "proxy": {
            "enabled": defaults.proxy.enabled,
            "url": defaults.proxy.url,
        },
        "output": {
            "report_dir": defaults.output.report_dir,
            "log_level": defaults.output.log_level,
        },
    }


def load_settings(config_path: str | None = None) -> Settings:
    defaults = _defaults_dict()
    config_file = Path(config_path) if config_path else Path("config.yaml")
    loaded: dict[str, Any] = {}

    if config_file.exists():
        loaded = yaml.safe_load(config_file.read_text(encoding="utf-8")) or {}

    merged = _deep_merge(defaults, loaded)

    merged["anthropic_api_key"] = os.getenv(
        "ANTHROPIC_API_KEY",
        merged.get("anthropic_api_key", ""),
    )
    merged["gemini_api_key"] = os.getenv(
        "GEMINI_API_KEY",
        merged.get("gemini_api_key", ""),
    )
    merged["ai"]["model"] = os.getenv("PHANTOMAI_MODEL", merged["ai"]["model"])
    merged["ai"]["max_tokens"] = int(
        os.getenv("PHANTOMAI_MAX_TOKENS", str(merged["ai"]["max_tokens"]))
    )

    if os.getenv("PHANTOMAI_PROXY_URL"):
        merged["proxy"]["enabled"] = True
        merged["proxy"]["url"] = os.getenv("PHANTOMAI_PROXY_URL", "")

    return Settings(
        anthropic_api_key=merged["anthropic_api_key"],
        gemini_api_key=merged["gemini_api_key"],
        ai=AISettings(**merged["ai"]),
        scan=ScanSettings(**merged["scan"]),
        proxy=ProxySettings(**merged["proxy"]),
        output=OutputSettings(**merged["output"]),
    )
