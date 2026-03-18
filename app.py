import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template_string
from requests.auth import HTTPBasicAuth

app = Flask(__name__)

SOURCE_URL = "https://www.rymdweb.com/domain/snapback/?action=date"
MOZ_API_URL = "https://lsapi.seomoz.com/v2/url_metrics"
DOMAIN_PATTERN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:se|nu)\b", re.IGNORECASE)
MAX_DOMAINS = 25

TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Expired Domain Metrics</title>
    <style>
      body {
        font-family: Arial, sans-serif;
        background: #f4f7fb;
        color: #1f2937;
        margin: 0;
        padding: 24px;
      }
      .container {
        max-width: 960px;
        margin: 0 auto;
        background: #ffffff;
        border-radius: 12px;
        box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08);
        padding: 24px;
      }
      h1 {
        margin-top: 0;
      }
      p.meta {
        color: #4b5563;
      }
      table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 20px;
      }
      th, td {
        text-align: left;
        padding: 12px 14px;
        border-bottom: 1px solid #e5e7eb;
      }
      th {
        background: #111827;
        color: #ffffff;
      }
      .tooltip {
        position: relative;
        display: inline-block;
        cursor: help;
        border-bottom: 1px dotted rgba(255, 255, 255, 0.7);
      }
      .tooltip .tooltiptext {
        visibility: hidden;
        width: 280px;
        background: #1f2937;
        color: #ffffff;
        text-align: left;
        border-radius: 8px;
        padding: 10px 12px;
        position: absolute;
        z-index: 1;
        bottom: 125%;
        left: 50%;
        margin-left: -140px;
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.25);
        font-weight: normal;
        line-height: 1.4;
        opacity: 0;
        transition: opacity 0.2s ease-in-out;
      }
      .tooltip:hover .tooltiptext {
        visibility: visible;
        opacity: 1;
      }
      tr:nth-child(even) {
        background: #f9fafb;
      }
      .error {
        margin-top: 16px;
        padding: 12px 14px;
        background: #fef2f2;
        color: #991b1b;
        border: 1px solid #fecaca;
        border-radius: 8px;
      }
      .empty {
        margin-top: 16px;
        color: #6b7280;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>Expired Domains with Moz Metrics</h1>
      <p class="meta">Showing up to {{ scraped_count }} scraped domains from rymdweb.com.</p>

      {% if error %}
        <div class="error">{{ error }}</div>
      {% endif %}

      {% if rows %}
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>
                <span class="tooltip">Domain Authority (DA)
                  <span class="tooltiptext">1-100 score predicting how well a website will rank on search engines. Based largely on link quality. Higher is better.</span>
                </span>
              </th>
              <th>
                <span class="tooltip">Linking Root Domains
                  <span class="tooltiptext">The total number of unique websites linking to this domain. A higher number indicates a more diverse, trustworthy, and natural link profile.</span>
                </span>
              </th>
            </tr>
          </thead>
          <tbody>
            {% for row in rows %}
              <tr>
                <td>{{ row.target }}</td>
                <td>{{ row.domain_authority if row.domain_authority is not none else 'N/A' }}</td>
                <td>{{ row.root_domains_linking_to_root_domain if row.root_domains_linking_to_root_domain is not none else 'N/A' }}</td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      {% else %}
        <p class="empty">No domains were found.</p>
      {% endif %}
    </div>
  </body>
</html>
"""


def scrape_domains(limit: int = MAX_DOMAINS) -> List[str]:
    """Fetch the expired-domain page and return up to `limit` unique .se/.nu domains."""
    response = requests.get(SOURCE_URL, timeout=20)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")
    extracted: List[str] = []
    seen = set()

    selectors = ["table td", "table th", "tbody td", "a", "tr"]

    for selector in selectors:
        for element in soup.select(selector):
            text = " ".join(element.stripped_strings)
            for match in DOMAIN_PATTERN.findall(text):
                domain = match.lower().strip()
                if domain not in seen:
                    seen.add(domain)
                    extracted.append(domain)
                    if len(extracted) >= limit:
                        return extracted

    page_text = soup.get_text(" ", strip=True)
    for match in DOMAIN_PATTERN.findall(page_text):
        domain = match.lower().strip()
        if domain not in seen:
            seen.add(domain)
            extracted.append(domain)
            if len(extracted) >= limit:
                break

    return extracted



def normalize_domain(value: Optional[str]) -> str:
    if not value:
        return ""

    cleaned = value.strip().lower()
    if not cleaned:
        return ""

    if cleaned.startswith(("http://", "https://")):
        parsed = urlparse(cleaned)
        cleaned = parsed.netloc or parsed.path

    return cleaned.strip().strip("/")



def get_moz_auth_options() -> List[Dict[str, Any]]:
    """Build Moz request auth settings from environment variables."""
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
        if key in item and item.get(key) is not None:
            return item.get(key)
        if key in metrics and metrics.get(key) is not None:
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
        if any(k in data for k in ("target", "domain_authority", "metrics")):
            return [data]
    return []



def fetch_moz_metrics(domains: List[str]) -> List[Dict[str, Any]]:
    """Fetch Moz metrics for a list of domains."""
    if not domains:
        return []

    response = None
    auth_errors = []
    auth_options = get_moz_auth_options()
    for index, auth_kwargs in enumerate(auth_options, start=1):
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

    data = response.json()
    results = extract_results(data)
    app.logger.info("Moz returned %s metric rows for %s targets.", len(results), len(domains))
    if results:
        app.logger.info("Moz result keys sample: %s", sorted(results[0].keys()))

    output: List[Dict[str, Any]] = []
    for index, domain in enumerate(domains):
        item = results[index] if index < len(results) else {}
        target = normalize_domain(
            item.get("target")
            or item.get("normalized_target")
            or item.get("url")
            or item.get("page")
            or domain
        )
        output.append(
            {
                "target": target or normalize_domain(domain),
                "domain_authority": pick_metric(item, "domain_authority"),
                "root_domains_linking_to_root_domain": pick_metric(
                    item,
                    "root_domains_linking_to_root_domain",
                    "root_domains_to_root_domain",
                    "linking_root_domains",
                ),
            }
        )

    return output


def sort_rows_by_domain_authority(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        rows,
        key=lambda row: (
            row.get("domain_authority") is None,
            -(row.get("domain_authority") or 0),
        ),
    )


@app.route("/")
def index():
    rows: List[Dict[str, Any]] = []
    domains: List[str] = []
    error = None

    try:
        domains = scrape_domains()
    except Exception as exc:  # Keep the page responsive even if scraping fails.
        error = str(exc)
        return render_template_string(TEMPLATE, rows=rows, error=error, scraped_count=0)

    try:
        rows = sort_rows_by_domain_authority(fetch_moz_metrics(domains))
    except Exception as exc:  # Show scraped domains even if Moz metrics fail.
        error = str(exc)
        rows = sort_rows_by_domain_authority([
            {
                "target": domain,
                "domain_authority": None,
                "root_domains_linking_to_root_domain": None,
            }
            for domain in domains
        ])

    return render_template_string(TEMPLATE, rows=rows, error=error, scraped_count=len(domains))


if __name__ == "__main__":
    app.run(debug=True)
