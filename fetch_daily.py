import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth

from app import app
from models import Domain, db

SOURCE_URL = "https://www.rymdweb.com/domain/snapback/?action=date"
MOZ_API_URL = "https://lsapi.seomoz.com/v2/url_metrics"
DOMAIN_PATTERN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:se|nu)\b", re.IGNORECASE)


def scrape_domains(limit: Optional[int] = None) -> List[str]:
    response = requests.get(SOURCE_URL, timeout=20)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")
    extracted: List[str] = []
    seen = set()

    for selector in ("table td", "table th", "tbody td", "a", "tr"):
        for element in soup.select(selector):
            text = " ".join(element.stripped_strings)
            for match in DOMAIN_PATTERN.findall(text):
                domain = match.lower().strip()
                if domain not in seen:
                    seen.add(domain)
                    extracted.append(domain)
                    if limit and len(extracted) >= limit:
                        return extracted

    page_text = soup.get_text(" ", strip=True)
    for match in DOMAIN_PATTERN.findall(page_text):
        domain = match.lower().strip()
        if domain not in seen:
            seen.add(domain)
            extracted.append(domain)
            if limit and len(extracted) >= limit:
                break

    return extracted



def normalize_domain(value: Optional[str]) -> str:
    if not value:
        return ""

    cleaned = value.strip().lower()
    if cleaned.startswith(("http://", "https://")):
        parsed = urlparse(cleaned)
        cleaned = parsed.netloc or parsed.path

    return cleaned.strip().strip("/")



def get_moz_auth_options() -> List[Dict[str, Any]]:
    api_token = (os.environ.get("MOZ_API_TOKEN") or os.environ.get("Moz-api-token") or "").strip()
    if api_token:
        normalized = api_token.lower()
        if normalized.startswith("basic ") or normalized.startswith("bearer "):
            return [{"headers": {"Authorization": api_token}}]
        if ":" in api_token:
            access_id, secret_key = api_token.split(":", 1)
            return [{"auth": HTTPBasicAuth(access_id.strip(), secret_key.strip())}]
        return [
            {"headers": {"Authorization": f"Basic {api_token}"}},
            {"headers": {"x-moz-token": api_token}},
        ]

    access_id = (os.environ.get("MOZ_ACCESS_ID") or "").strip()
    secret_key = (os.environ.get("MOZ_SECRET_KEY") or "").strip()
    if access_id and secret_key:
        return [{"auth": HTTPBasicAuth(access_id, secret_key)}]

    raise RuntimeError(
        "Set MOZ_API_TOKEN / Moz-api-token to your Moz token, or set MOZ_ACCESS_ID and MOZ_SECRET_KEY."
    )



def pick_metric(item: Dict[str, Any], *keys: str) -> Any:
    metrics = item.get("metrics") if isinstance(item.get("metrics"), dict) else {}
    for key in keys:
        if item.get(key) is not None:
            return item.get(key)
        if metrics.get(key) is not None:
            return metrics.get(key)
    return None



def extract_results(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("results", "url_metrics", "data"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        if any(key in data for key in ("target", "domain_authority", "metrics")):
            return [data]
    return []



def fetch_moz_metrics(domains: List[str]) -> List[Dict[str, Any]]:
    if not domains:
        return []

    response = None
    auth_errors = []
    for index, auth_kwargs in enumerate(get_moz_auth_options(), start=1):
        candidate = requests.post(
            MOZ_API_URL,
            json={"targets": domains},
            timeout=30,
            **auth_kwargs,
        )
        if candidate.ok:
            response = candidate
            break
        if candidate.status_code in (401, 403):
            auth_errors.append(f"option {index} returned {candidate.status_code}")
            continue
        candidate.raise_for_status()

    if response is None:
        raise RuntimeError(
            "Moz authentication failed. Tried: " + "; ".join(auth_errors or ["no auth options available"])
        )

    results = extract_results(response.json())
    output: List[Dict[str, Any]] = []
    for index, domain in enumerate(domains):
        item = results[index] if index < len(results) else {}
        output.append(
            {
                "domain_name": normalize_domain(item.get("target") or item.get("normalized_target") or item.get("url") or domain),
                "da": pick_metric(item, "domain_authority"),
                "linking_root_domains": pick_metric(
                    item,
                    "root_domains_linking_to_root_domain",
                    "root_domains_to_root_domain",
                    "linking_root_domains",
                ),
            }
        )
    return output



def refresh_daily_domains() -> None:
    today = datetime.now(timezone.utc).date()
    domains = scrape_domains()
    metrics = fetch_moz_metrics(domains)

    with app.app_context():
        db.create_all()
        Domain.query.filter(Domain.fetch_date < today).delete()
        Domain.query.filter_by(fetch_date=today).delete()

        for item in metrics:
            db.session.add(
                Domain(
                    domain_name=item["domain_name"],
                    da=item["da"],
                    linking_root_domains=item["linking_root_domains"],
                    fetch_date=today,
                )
            )

        db.session.commit()
        print(f"Saved {len(metrics)} domains for {today}.")


if __name__ == "__main__":
    refresh_daily_domains()
