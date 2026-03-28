import os
import smtplib
from datetime import date, datetime, timezone
from email.message import EmailMessage
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from requests.auth import HTTPBasicAuth

from app import app, ensure_database_schema, fetch_release_date, scrape_domains
from models import Domain, User, db

MOZ_API_URL = "https://lsapi.seomoz.com/v2/url_metrics"
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9,sv;q=0.8",
}



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

    moz_targets = [domain if domain.startswith(("http://", "https://")) else f"https://{domain}" for domain in domains]

    response = None
    auth_errors = []
    for index, auth_kwargs in enumerate(get_moz_auth_options(), start=1):
        candidate = requests.post(
            MOZ_API_URL,
            json={"targets": moz_targets},
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



def send_email(recipient: str, subject: str, body: str) -> None:
    smtp_host = (os.environ.get("SMTP_HOST") or "").strip()
    smtp_port = int((os.environ.get("SMTP_PORT") or "587").strip())
    smtp_user = (os.environ.get("SMTP_USER") or "").strip()
    smtp_password = (os.environ.get("SMTP_PASSWORD") or "").strip()
    smtp_from = (os.environ.get("SMTP_FROM_EMAIL") or smtp_user).strip()
    smtp_use_tls = (os.environ.get("SMTP_USE_TLS", "true").strip().lower() != "false")

    if not smtp_host or not smtp_from:
        raise RuntimeError("SMTP is not configured. Set SMTP_HOST and SMTP_FROM_EMAIL (or SMTP_USER).")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = smtp_from
    message["To"] = recipient
    message.set_content(body)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
        if smtp_use_tls:
            server.starttls()
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
        server.send_message(message)


def send_premium_da_alerts(active_date: date) -> None:
    premium_users = User.query.filter_by(is_premium=True, da_alert_enabled=True).all()
    if not premium_users:
        print("No premium DA alerts enabled.")
        return

    for user in premium_users:
        if user.da_alert_last_sent == active_date:
            continue

        threshold = user.da_alert_threshold or 15
        matching_domains = (
            Domain.query.filter(
                ((Domain.release_date == active_date) | ((Domain.release_date.is_(None)) & (Domain.fetch_date == active_date))),
                Domain.da.isnot(None),
                Domain.da >= threshold,
            )
            .order_by(Domain.da.desc(), Domain.domain_name.asc())
            .limit(200)
            .all()
        )

        if not matching_domains:
            continue

        lines = [
            "Hi,",
            "",
            f"Here is your daily domain alert for {active_date.isoformat()}.",
            f"Threshold: DA >= {threshold}",
            "",
            "Matching domains:",
        ]
        lines.extend(f"- {domain.domain_name} (DA {domain.da})" for domain in matching_domains)
        lines.extend(["", "You can update this threshold from your membership page at any time."])

        try:
            send_email(
                recipient=user.email,
                subject=f"Your DA alert: {len(matching_domains)} domains above DA {threshold}",
                body="\n".join(lines),
            )
            user.da_alert_last_sent = active_date
            db.session.commit()
            print(f"Sent DA alert email to {user.email} with {len(matching_domains)} domains.")
        except Exception as exc:
            db.session.rollback()
            print(f"Failed to send DA alert email to {user.email}: {exc}")


def refresh_daily_domains() -> None:
    today = datetime.now(timezone.utc).date()

    # 1. Fetch release date from site
    try:
        release_date_text = fetch_release_date()
        release_date_value = date.fromisoformat(release_date_text) if release_date_text else today
    except Exception as e:
        print(f"Date parse failed: {e}. Using today's date.")
        release_date_value = today

    # 2. Scrape all available domains from the official feeds
    print("Scraping all available domains...")
    domains = scrape_domains(release_date=release_date_value.isoformat())

    if not domains:
        print("No domains found. Aborting.")
        return

    # 3. Fetch metrics for a limited subset to avoid oversized Moz requests
    metric_targets = domains[:25]
    metrics_by_domain: Dict[str, Dict[str, Any]] = {}
    try:
        print(f"Fetching Moz metrics for {len(metric_targets)} domains...")
        metrics_by_domain = {
            item["domain_name"]: item
            for item in fetch_moz_metrics(metric_targets)
        }
    except Exception as e:
        print(f"Moz API Error: {e}. Saving domains without metrics.")

    all_metrics = [
        {
            "domain_name": domain,
            "da": metrics_by_domain.get(domain, {}).get("da"),
            "linking_root_domains": metrics_by_domain.get(domain, {}).get("linking_root_domains"),
        }
        for domain in domains
    ]

    # 4. Save to Database
    with app.app_context():
        ensure_database_schema()

        # Only clear today's specific run to prevent duplicates
        Domain.query.filter_by(fetch_date=today).delete()

        for item in all_metrics:
            db.session.add(
                Domain(
                    domain_name=item["domain_name"],
                    da=item["da"],
                    linking_root_domains=item["linking_root_domains"],
                    fetch_date=today,
                    release_date=release_date_value,
                )
            )

        db.session.commit()
        send_premium_da_alerts(release_date_value)
        print(f"✅ Success! Saved {len(all_metrics)} domains for {today}.")


if __name__ == "__main__":
    refresh_daily_domains()
