import os
import re
from typing import List, Dict, Any

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
              <th>Domain Authority (DA)</th>
              <th>Linking Root Domains</th>
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

    selectors = [
        "table td",
        "table th",
        "tbody td",
        "a",
        "tr",
    ]

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


def get_moz_auth_kwargs() -> Dict[str, Any]:
    """Build Moz request auth settings from environment variables."""
    api_token = (os.environ.get("MOZ_API_TOKEN") or os.environ.get("Moz-api-token") or "").strip()
    if api_token:
        normalized = api_token.lower()
        if normalized.startswith("basic ") or normalized.startswith("bearer "):
            return {
                "headers": {
                    "Authorization": api_token,
                }
            }
        if ":" in api_token:
            access_id, secret_key = api_token.split(":", 1)
            return {
                "auth": HTTPBasicAuth(access_id, secret_key),
            }
        return {
            "headers": {
                "Authorization": f"Basic {api_token}",
            }
        }

    access_id = os.environ.get("MOZ_ACCESS_ID")
    secret_key = os.environ.get("MOZ_SECRET_KEY")
    if access_id and secret_key:
        return {
            "auth": HTTPBasicAuth(access_id.strip(), secret_key.strip()),
        }

    raise RuntimeError(
        "Set MOZ_API_TOKEN / Moz-api-token to your Moz basic-auth token, or set MOZ_ACCESS_ID and MOZ_SECRET_KEY."
    )



def fetch_moz_metrics(domains: List[str]) -> List[Dict[str, Any]]:
    """Fetch Moz metrics for a list of domains."""
    if not domains:
        return []

    response = requests.post(
        MOZ_API_URL,
        json={"targets": domains},
        timeout=30,
        **get_moz_auth_kwargs(),
    )
    response.raise_for_status()

    data = response.json()
    results = data if isinstance(data, list) else data.get("results", [])

    metrics_by_target: Dict[str, Dict[str, Any]] = {}
    for item in results:
        target = (item.get("target") or item.get("url") or "").lower()
        if not target:
            continue
        metrics_by_target[target] = {
            "target": target,
            "domain_authority": item.get("domain_authority"),
            "root_domains_linking_to_root_domain": item.get("root_domains_linking_to_root_domain"),
        }

    return [
        metrics_by_target.get(
            domain.lower(),
            {
                "target": domain.lower(),
                "domain_authority": None,
                "root_domains_linking_to_root_domain": None,
            },
        )
        for domain in domains
    ]


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
        rows = fetch_moz_metrics(domains)
    except Exception as exc:  # Show scraped domains even if Moz metrics fail.
        error = str(exc)
        rows = [
            {
                "target": domain,
                "domain_authority": None,
                "root_domains_linking_to_root_domain": None,
            }
            for domain in domains
        ]

    return render_template_string(TEMPLATE, rows=rows, error=error, scraped_count=len(domains))


if __name__ == "__main__":
    app.run(debug=True)
