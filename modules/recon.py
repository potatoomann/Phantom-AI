import httpx

from config import Settings
from utils import extract_host


async def run_recon(target: str, settings: Settings) -> dict:
    """Run passive recon using public certificate and DNS datasets."""
    domain = extract_host(target)
    subdomains = set()

    async with httpx.AsyncClient(
        timeout=settings.scan.timeout,
        headers={"User-Agent": settings.scan.user_agent},
        verify=settings.scan.verify_tls,
        proxy=settings.proxy.url if settings.proxy.enabled else None,
        follow_redirects=False,
    ) as client:
        try:
            resp = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if resp.status_code == 200:
                for entry in resp.json():
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        candidate = sub.strip().lstrip("*.")
                        if candidate.endswith(domain):
                            subdomains.add(candidate)
        except Exception:
            pass

        try:
            resp = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    parts = line.split(",")
                    if parts:
                        subdomains.add(parts[0].strip())
        except Exception:
            pass

    ordered = sorted(subdomains)[: settings.scan.max_subdomains]
    return {
        "target": target,
        "domain": domain,
        "subdomains": ordered,
        "subdomain_count": len(ordered),
    }
