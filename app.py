import os
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import requests
import stripe
from flask import Flask, abort, redirect, render_template, render_template_string, request, session, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from requests.auth import HTTPBasicAuth

from models import Domain, User, db

SE_DOMAINS_JSON_URL = "https://data.internetstiftelsen.se/bardate_domains.json"
NU_DOMAINS_JSON_URL = "https://data.internetstiftelsen.se/bardate_domains_nu.json"
MOZ_API_URL = "https://lsapi.seomoz.com/v2/url_metrics"
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9,sv;q=0.8",
}


def normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql://", 1)
    return database_url


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = normalize_database_url(
    os.environ.get("DATABASE_URL", "sqlite:///app.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

def get_stripe_publishable_key() -> str:
    return (os.environ.get("STRIPE_PUBLISHABLE_KEY") or os.environ.get("Publishable_key_test") or "").strip()



def get_stripe_secret_key() -> str:
    return (os.environ.get("STRIPE_SECRET_KEY") or os.environ.get("Secret_key_test") or "").strip()



def get_stripe_price_id() -> str:
    return (
        os.environ.get("STRIPE_PRICE_ID")
        or os.environ.get("STRIPE_PRICE_ID_TEST")
        or os.environ.get("Price_id_test")
        or ""
    ).strip()


stripe.api_key = get_stripe_secret_key()




def fetch_release_date():
    return (datetime.now(timezone.utc).date() + timedelta(days=1)).isoformat()


def normalize_scraped_domain(value: str, suffix: str):
    normalized = value.strip().lower().strip(".")
    if normalized.startswith(("http://", "https://")):
        normalized = normalized.split("://", 1)[1]
    normalized = normalized.strip("/")
    if normalized.startswith("www."):
        normalized = normalized[4:]
    if not normalized.endswith(suffix):
        return None
    return normalized


def extract_domains_from_payload(payload, suffix: str):
    domains = []
    queue = [payload]
    seen_values = set()

    while queue:
        current = queue.pop(0)
        if isinstance(current, list):
            queue.extend(current)
            continue
        if isinstance(current, dict):
            for value in current.values():
                queue.append(value)
            continue
        if not isinstance(current, str):
            continue

        normalized = normalize_scraped_domain(current, suffix)
        if normalized and normalized not in seen_values:
            seen_values.add(normalized)
            domains.append(normalized)

    return domains


def scrape_domains(limit: int | None = None):
    sources = (
        (SE_DOMAINS_JSON_URL, ".se"),
        (NU_DOMAINS_JSON_URL, ".nu"),
    )

    extracted = []
    seen = set()
    errors = []

    for url, suffix in sources:
        try:
            response = requests.get(url, headers=REQUEST_HEADERS, timeout=20)
            response.raise_for_status()
            candidates = extract_domains_from_payload(response.json(), suffix)
        except Exception as exc:
            errors.append(f"{url}: {exc}")
            continue

        for domain in candidates:
            if domain in seen:
                continue
            seen.add(domain)
            extracted.append(domain)
            if limit and len(extracted) >= limit:
                return extracted

    if not extracted and errors:
        raise RuntimeError("Could not fetch domains from Internetstiftelsen sources: " + "; ".join(errors))

    return extracted



def get_moz_auth_options():
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

    return []



def pick_metric(item, *keys):
    metrics = item.get("metrics") if isinstance(item.get("metrics"), dict) else {}
    for key in keys:
        if item.get(key) is not None:
            return item.get(key)
        if metrics.get(key) is not None:
            return metrics.get(key)
    return None



def extract_results(data):
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



def fetch_moz_metrics(domains):
    if not domains:
        return []

    auth_options = get_moz_auth_options()
    if not auth_options:
        return []

    moz_targets = [domain if domain.startswith(("http://", "https://")) else f"https://{domain}" for domain in domains]
    response = None
    for auth_kwargs in auth_options:
        try:
            candidate = requests.post(
                MOZ_API_URL,
                json={"targets": moz_targets},
                timeout=30,
                **auth_kwargs,
            )
        except requests.RequestException:
            continue

        if candidate.ok:
            response = candidate
            break
        if candidate.status_code in (401, 403):
            continue
        return []

    if response is None:
        return []

    results = extract_results(response.json())
    output = []
    for index, domain in enumerate(domains):
        item = results[index] if index < len(results) else {}
        output.append(
            {
                "domain_name": domain,
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



def hydrate_visible_domains(domains, fetch_date):
    metrics = fetch_moz_metrics([domain.domain_name for domain in domains])
    if not metrics:
        return domains

    metrics_by_domain = {item["domain_name"]: item for item in metrics}
    any_values = False
    for domain in domains:
        metric = metrics_by_domain.get(domain.domain_name)
        if metric is None:
            continue
        domain.da = metric["da"]
        domain.linking_root_domains = metric["linking_root_domains"]
        if domain.da is not None or domain.linking_root_domains is not None:
            any_values = True

    if any_values and fetch_date is not None:
        if db.session.get_bind() is not None:
            if not Domain.query.filter_by(fetch_date=fetch_date).first():
                for domain in domains:
                    db.session.add(
                        Domain(
                            domain_name=domain.domain_name,
                            da=domain.da,
                            linking_root_domains=domain.linking_root_domains,
                            fetch_date=fetch_date,
                        )
                    )
                db.session.commit()
            else:
                db.session.commit()

    return domains





def ensure_today_domain_snapshot(scraped_domains, visible_domains, fetch_date, release_date_value):
    if not scraped_domains or fetch_date is None:
        return

    existing_rows = Domain.query.filter_by(fetch_date=fetch_date).all()
    if len(existing_rows) >= len(scraped_domains):
        return

    existing_domains = {row.domain_name for row in existing_rows}
    visible_map = {domain.domain_name: domain for domain in visible_domains}

    for domain_name in scraped_domains:
        if domain_name in existing_domains:
            continue
        visible_row = visible_map.get(domain_name)
        db.session.add(
            Domain(
                domain_name=domain_name,
                da=getattr(visible_row, "da", None),
                linking_root_domains=getattr(visible_row, "linking_root_domains", None),
                fetch_date=fetch_date,
                release_date=release_date_value,
            )
        )

    db.session.commit()

USER_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <title>User Page</title>
    <style>
      :root {
        --background: 0 0% 100%;
        --foreground: 222.2 84% 4.9%;
        --card: 0 0% 100%;
        --card-foreground: 222.2 84% 4.9%;
        --primary: 222.2 47.4% 11.2%;
        --primary-foreground: 210 40% 98%;
        --secondary: 210 40% 96.1%;
        --secondary-foreground: 222.2 47.4% 11.2%;
        --muted: 210 40% 96.1%;
        --muted-foreground: 215.4 16.3% 46.9%;
        --accent: 210 40% 96.1%;
        --accent-foreground: 222.2 47.4% 11.2%;
        --border: 214.3 31.8% 91.4%;
      }

      .dark {
        --background: 222.2 84% 4.9%;
        --foreground: 210 40% 98%;
        --card: 222.2 47.4% 11.2%;
        --card-foreground: 210 40% 98%;
        --primary: 210 40% 98%;
        --primary-foreground: 222.2 47.4% 11.2%;
        --secondary: 217.2 32.6% 17.5%;
        --secondary-foreground: 210 40% 98%;
        --muted: 217.2 32.6% 17.5%;
        --muted-foreground: 215 20.2% 65.1%;
        --accent: 217.2 32.6% 17.5%;
        --accent-foreground: 210 40% 98%;
        --border: 217.2 32.6% 17.5%;
      }

      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        transition: background-color 0.3s ease, color 0.3s ease;
      }
      a { color: inherit; text-decoration: none; }
      button { font: inherit; }

      .bg-background {
        background: hsl(var(--background));
        color: hsl(var(--foreground));
      }
      .bg-card {
        background: hsl(var(--card));
        transition: background-color 0.3s ease, color 0.3s ease;
      }
      .text-card-foreground { color: hsl(var(--card-foreground)); }
      .text-muted-foreground { color: hsl(var(--muted-foreground)); }
      .border-border { border-color: hsl(var(--border)); }
      .rounded-xl { border-radius: 0.75rem; }
      .rounded-md { border-radius: 0.375rem; }

      .app-shell {
        min-height: 100vh;
        display: flex;
        flex-direction: column;
      }
      .header {
        position: sticky;
        top: 0;
        z-index: 10;
        border-bottom: 1px solid hsl(var(--border));
        background: hsl(var(--background));
      }
      .header-inner,
      .container {
        max-width: 1200px;
        width: 100%;
        margin: 0 auto;
      }
      .header-inner {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        padding: 14px 18px;
      }
      .header-left { min-width: 0; }
      .header-right {
        display: flex;
        align-items: center;
        gap: 16px;
      }
      .header-link {
        color: hsl(var(--muted-foreground));
        font-weight: 500;
        text-decoration: none;
      }
      .icon-button,
      .user-trigger,
      .action-button {
        border: 1px solid hsl(var(--border));
        background: hsl(var(--card));
        color: hsl(var(--card-foreground));
      }
      .icon-button,
      .user-trigger {
        width: 40px;
        min-height: 40px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        padding: 0;
        cursor: pointer;
      }
      .action-button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 38px;
        padding: 8px 16px;
        border-radius: 6px;
        font-weight: 500;
      }
      .action-button.primary {
        background: hsl(var(--primary));
        color: hsl(var(--primary-foreground));
        border-color: transparent;
      }
      .page {
        padding: 18px;
      }
      .container {
        display: grid;
        gap: 18px;
      }
      .page-head h1 {
        margin: 0;
        font-size: 1.5rem;
        line-height: 1.1;
        letter-spacing: -0.03em;
      }
      .page-head p,
      .card-meta,
      .account-panel p {
        color: hsl(var(--muted-foreground));
      }
      .page-head p {
        margin: 6px 0 0;
        font-size: 0.9rem;
      }
      .metrics-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 14px;
      }
      .metric-card,
      .account-panel {
        border: 1px solid hsl(var(--border));
        padding: 16px;
      }
      .card-title {
        font-size: 0.82rem;
        margin-bottom: 8px;
      }
      .card-value {
        font-size: 1.7rem;
        font-weight: 700;
        letter-spacing: -0.04em;
        word-break: break-word;
      }
      .card-meta {
        margin-top: 8px;
        font-size: 0.8rem;
      }
      .account-panel h2 {
        margin: 0 0 6px;
        font-size: 1rem;
      }
      .account-panel p {
        margin: 0 0 18px;
        font-size: 0.88rem;
      }
      .details-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 14px;
      }
      .detail-card {
        border: 1px solid hsl(var(--border));
        border-radius: 0.75rem;
        padding: 14px;
      }
      .detail-label {
        font-size: 0.75rem;
        color: hsl(var(--muted-foreground));
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 8px;
      }
      .detail-value {
        font-weight: 600;
        word-break: break-word;
      }
      .badge {
        display: inline-flex;
        align-items: center;
        min-height: 24px;
        padding: 0 8px;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 500;
        background: hsl(var(--primary) / 0.1);
        color: hsl(var(--primary));
      }
      .actions {
        display: flex;
        gap: 12px;
        flex-wrap: wrap;
        margin-top: 18px;
      }
      .theme-icon {
        width: 18px;
        height: 18px;
      }
      .theme-icon.moon { display: none; }
      .dark .theme-icon.sun { display: none; }
      .dark .theme-icon.moon { display: block; }
      details.user-menu { position: relative; }
      .dropdown {
        position: absolute;
        right: 0;
        top: calc(100% + 8px);
        min-width: 160px;
        border: 1px solid hsl(var(--border));
        background: hsl(var(--card));
        border-radius: 0.75rem;
        padding: 6px;
        display: grid;
        gap: 4px;
      }
      .dropdown a {
        min-height: 34px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border-radius: 0.5rem;
        color: hsl(var(--muted-foreground));
      }
      .dropdown a:hover {
        background: hsl(var(--accent));
        color: hsl(var(--accent-foreground));
      }
      @media (max-width: 980px) {
        .metrics-grid,
        .details-grid {
          grid-template-columns: 1fr;
        }
      }
      @media (max-width: 720px) {
        .header-inner,
        .page {
          padding-left: 12px;
          padding-right: 12px;
        }
        .header-inner,
        .header-right,
        .actions {
          flex-wrap: wrap;
        }
      }
    </style>
  </head>
  <body class="bg-background">
    <div class="app-shell">
      <header class="header bg-background">
        <div class="header-inner">
          <div class="header-left">
            <div class="page-head">
              <h1>Domain Intelligence</h1>
              <p class="text-muted-foreground">Daily curated list of expiring domains, ranked by SEO authority.</p>
            </div>
          </div>
          <div class="header-right">
            <a class="header-link" href="{{ url_for('index') }}">Domains</a>
            <a class="header-link" href="{{ url_for('logout') }}">Logout</a>
            <button class="icon-button rounded-md" type="button" id="theme-toggle" aria-label="Toggle theme">
              <svg class="theme-icon sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="4"></circle>
                <path d="M12 2v2.5"></path>
                <path d="M12 19.5V22"></path>
                <path d="M4.93 4.93l1.77 1.77"></path>
                <path d="M17.3 17.3l1.77 1.77"></path>
                <path d="M2 12h2.5"></path>
                <path d="M19.5 12H22"></path>
                <path d="M4.93 19.07l1.77-1.77"></path>
                <path d="M17.3 6.7l1.77-1.77"></path>
              </svg>
              <svg class="theme-icon moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"></path>
              </svg>
            </button>
            <details class="user-menu">
              <summary class="user-trigger rounded-md" aria-label="Profile menu">{{ user.email[0]|upper }}</summary>
              <div class="dropdown text-card-foreground">
                <a href="{{ url_for('user_page') }}">{{ user.email }}</a>
                <a href="{{ url_for('logout') }}">Logout</a>
              </div>
            </details>
          </div>
        </div>
      </header>

      <main class="page">
        <div class="container">
          <section class="metrics-grid">
            <article class="metric-card bg-card text-card-foreground border-border rounded-xl">
              <div class="card-title text-muted-foreground">Email</div>
              <div class="card-value">{{ user.email }}</div>
              <div class="card-meta text-muted-foreground">Primary account identity</div>
            </article>
            <article class="metric-card bg-card text-card-foreground border-border rounded-xl">
              <div class="card-title text-muted-foreground">Membership</div>
              <div class="card-value">{{ 'Premium' if user.is_premium else 'Free' }}</div>
              <div class="card-meta text-muted-foreground">Current access level</div>
            </article>
            <article class="metric-card bg-card text-card-foreground border-border rounded-xl">
              <div class="card-title text-muted-foreground">Billing</div>
              <div class="card-value">{{ 'Manage in Stripe' if user.stripe_customer_id else 'Not connected' }}</div>
              <div class="card-meta text-muted-foreground">Invoices and cancellation</div>
            </article>
          </section>

          <section class="account-panel bg-card text-card-foreground border-border rounded-xl">
            <h2>Account Details</h2>
            <p>Manage your current access and billing settings from the same dashboard style as the main domain view.</p>
            <div class="details-grid">
              <div class="detail-card">
                <div class="detail-label">Email</div>
                <div class="detail-value">{{ user.email }}</div>
              </div>
              <div class="detail-card">
                <div class="detail-label">Plan</div>
                <div class="detail-value"><span class="badge">{{ 'Premium' if user.is_premium else 'Free' }}</span></div>
              </div>
              <div class="detail-card">
                <div class="detail-label">Billing</div>
                <div class="detail-value">{{ 'Invoices and cancellation' if user.stripe_customer_id else 'Available after checkout' }}</div>
              </div>
            </div>
            <div class="actions">
              {% if user.stripe_customer_id %}
                <a class="action-button rounded-md" href="{{ url_for('billing_portal') }}">Manage Billing</a>
              {% endif %}
              {% if not user.is_premium %}
                <a class="action-button primary" href="{{ url_for('checkout') }}">Upgrade to Premium</a>
              {% endif %}
              <a class="action-button rounded-md" href="{{ url_for('index') }}">Back to domains</a>
            </div>
          </section>
        </div>
      </main>
    </div>

    <script>
      (function () {
        const root = document.documentElement
        const themeKey = 'theme'
        const themeToggle = document.getElementById('theme-toggle')
        const savedTheme = window.localStorage.getItem(themeKey)
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches

        if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
          root.classList.add('dark')
        }

        if (themeToggle) {
          themeToggle.addEventListener('click', function () {
            root.classList.toggle('dark')
            window.localStorage.setItem(themeKey, root.classList.contains('dark') ? 'dark' : 'light')
          })
        }
      })()
    </script>
  </body>
</html>
"""

ADMIN_LOGIN_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Admin Login</title>
    <style>
      body { font-family: Inter, ui-sans-serif, system-ui, sans-serif; background: linear-gradient(180deg, #f8fafc 0%, #eef2ff 100%); padding: 32px; color: #0f172a; }
      .card { max-width: 420px; margin: 0 auto; background: rgba(255,255,255,0.92); border: 1px solid #e2e8f0; padding: 28px; border-radius: 24px; box-shadow: 0 24px 80px rgba(15, 23, 42, 0.08); }
      input { width: 100%; padding: 12px; margin: 8px 0 14px; border: 1px solid #d1d5db; border-radius: 14px; box-sizing: border-box; }
      button, a.button { display: inline-block; background: #0f172a; color: #fff; padding: 12px 16px; border-radius: 999px; text-decoration: none; border: 0; cursor: pointer; }
      .error { margin-bottom: 14px; color: #b91c1c; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>Admin Login</h1>
      {% if error %}<div class="error">{{ error }}</div>{% endif %}
      <form method="post">
        <label for="username">Username</label>
        <input id="username" name="username" type="text" required>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" required>
        <button type="submit">Login</button>
      </form>
      <p><a class="button" href="{{ url_for('index') }}">Back to domains</a></p>
    </div>
  </body>
</html>
"""

ADMIN_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Admin Page</title>
    <style>
      body { font-family: Inter, ui-sans-serif, system-ui, sans-serif; background: linear-gradient(180deg, #f8fafc 0%, #eef2ff 100%); padding: 32px; color: #0f172a; }
      .card { max-width: 1100px; margin: 0 auto; background: rgba(255,255,255,0.92); border: 1px solid #e2e8f0; padding: 28px; border-radius: 24px; box-shadow: 0 24px 80px rgba(15, 23, 42, 0.08); }
      .stats { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
      .stat { background: #f8fafc; border: 1px solid #e2e8f0; padding: 16px; border-radius: 18px; min-width: 180px; }
      .filters { display: grid; grid-template-columns: minmax(220px, 320px); gap: 12px; margin-top: 12px; align-items: end; }
      .filter-field { display: grid; gap: 6px; }
      .filter-field label { font-size: 0.85rem; color: #334155; font-weight: 600; }
      .filter-field input, .filter-field select { width: 100%; padding: 10px 12px; border: 1px solid #cbd5e1; border-radius: 12px; font: inherit; background: #fff; }
      .filter-meta { margin-top: 10px; color: #475569; font-size: 0.9rem; }
      .sortable { cursor: pointer; user-select: none; }
      .sortable.active { color: #1d4ed8; }
      .sort-arrow { margin-left: 6px; font-size: 0.8rem; color: #64748b; }
      table { width: 100%; border-collapse: collapse; margin-top: 16px; overflow: hidden; }
      th, td { text-align: left; padding: 12px 14px; border-bottom: 1px solid #e5e7eb; }
      th { background: #f8fafc; color: #0f172a; }
      a.button { display: inline-block; background: #0f172a; color: #fff; padding: 12px 16px; border-radius: 999px; text-decoration: none; margin-right: 12px; }
      @media (max-width: 900px) {
        .filters { grid-template-columns: 1fr; }
      }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>Admin Page</h1>
      <div class="stats">
        <div class="stat"><strong>Total users</strong><br>{{ total_users }}</div>
        <div class="stat"><strong>Premium users</strong><br>{{ premium_users }}</div>
        <div class="stat"><strong>Today's domains</strong><br>{{ today_domains }}</div>
      </div>
      <p>
        <a class="button" href="{{ url_for('index') }}">Back to domains</a>
        <a class="button" href="{{ url_for('admin_logout') }}">Admin logout</a>
      </p>
      <h2>Users</h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Email</th><th>Premium</th><th>Stripe Customer</th></tr>
        </thead>
        <tbody>
          {% for user in users %}
            <tr>
              <td>{{ user.id }}</td>
              <td>{{ user.email }}</td>
              <td>{{ 'Yes' if user.is_premium else 'No' }}</td>
              <td>{{ user.stripe_customer_id or '—' }}</td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
      <h2>Latest domains</h2>
      <div class="filters">
        <div class="filter-field">
          <label for="page-size-filter">Rows shown</label>
          <select id="page-size-filter">
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </div>
      </div>
      <div class="filter-meta" id="domains-count">{{ domains|length }} domains available</div>
      <table>
        <thead>
          <tr>
            <th>Domain</th>
            <th id="sort-da" class="sortable" data-sort-key="da">DA <span class="sort-arrow">↕</span></th>
            <th id="sort-lrd" class="sortable" data-sort-key="lrd">Linking Root Domains <span class="sort-arrow">↕</span></th>
            <th>Fetch Date</th>
          </tr>
        </thead>
        <tbody id="domain-rows">
          {% for domain in domains %}
            <tr data-da="{{ domain.da if domain.da is not none else '' }}" data-lrd="{{ domain.linking_root_domains if domain.linking_root_domains is not none else '' }}">
              <td>{{ domain.domain_name }}</td>
              <td>{{ domain.da if domain.da is not none else 'N/A' }}</td>
              <td>{{ domain.linking_root_domains if domain.linking_root_domains is not none else 'N/A' }}</td>
              <td>{{ domain.fetch_date }}</td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    <script>
      (function () {
        const pageSizeSelect = document.getElementById('page-size-filter')
        const tableBody = document.getElementById('domain-rows')
        const rows = Array.from(tableBody.querySelectorAll('tr'))
        const count = document.getElementById('domains-count')
        const sortDa = document.getElementById('sort-da')
        const sortLrd = document.getElementById('sort-lrd')
        let sortKey = null
        let sortDirection = 'desc'

        function getSortValue(row, key) {
          if (key === 'da') {
            return row.dataset.da === '' ? -1 : Number(row.dataset.da)
          }
          if (key === 'lrd') {
            return row.dataset.lrd === '' ? -1 : Number(row.dataset.lrd)
          }
          return 0
        }

        function setSortIndicator() {
          ;[sortDa, sortLrd].forEach((header) => {
            header.classList.remove('active')
            header.querySelector('.sort-arrow').textContent = '↕'
          })
          if (!sortKey) {
            return
          }
          const activeHeader = sortKey === 'da' ? sortDa : sortLrd
          activeHeader.classList.add('active')
          activeHeader.querySelector('.sort-arrow').textContent = sortDirection === 'desc' ? '↓' : '↑'
        }

        function renderRows() {
          const sortedRows = [...rows]
          if (sortKey) {
            sortedRows.sort((a, b) => {
              const aValue = getSortValue(a, sortKey)
              const bValue = getSortValue(b, sortKey)
              if (aValue === bValue) {
                return 0
              }
              if (sortDirection == 'desc') {
                return bValue - aValue
              }
              return aValue - bValue
            })
          }

          const pageSize = Number(pageSizeSelect.value)
          sortedRows.forEach((row, index) => {
            row.style.display = index < pageSize ? '' : 'none'
            tableBody.appendChild(row)
          })
          const shown = Math.min(pageSize, rows.length)
          if (sortKey) {
            const sortLabel = sortKey === 'da' ? 'DA' : 'Linking Root Domains'
            count.textContent = `Showing ${shown} of ${rows.length} domains (sorted by ${sortLabel} ${sortDirection.toUpperCase()})`
          } else {
            count.textContent = `Showing ${shown} of ${rows.length} domains`
          }
        }

        function toggleSort(key) {
          if (sortKey === key) {
            sortDirection = sortDirection === 'desc' ? 'asc' : 'desc'
          } else {
            sortKey = key
            sortDirection = 'desc'
          }
          setSortIndicator()
          renderRows()
        }

        pageSizeSelect.addEventListener('change', renderRows)
        sortDa.addEventListener('click', () => toggleSort('da'))
        sortLrd.addEventListener('click', () => toggleSort('lrd'))

        setSortIndicator()
        renderRows()
      })()
    </script>
  </body>
</html>
"""

AUTH_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }}</title>
    <style>
      body { font-family: Inter, ui-sans-serif, system-ui, sans-serif; background: linear-gradient(180deg, #f8fafc 0%, #eef2ff 100%); padding: 32px; color: #0f172a; }
      .card { max-width: 420px; margin: 0 auto; background: rgba(255,255,255,0.92); border: 1px solid #e2e8f0; padding: 28px; border-radius: 24px; box-shadow: 0 24px 80px rgba(15, 23, 42, 0.08); }
      input { width: 100%; padding: 12px; margin: 8px 0 14px; border: 1px solid #d1d5db; border-radius: 14px; box-sizing: border-box; }
      button, a.button { display: inline-block; background: #0f172a; color: #fff; padding: 12px 16px; border-radius: 999px; text-decoration: none; border: 0; cursor: pointer; }
      .error { margin-bottom: 14px; color: #b91c1c; }
      .meta { margin-top: 16px; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>{{ title }}</h1>
      {% if description %}<p class="meta">{{ description }}</p>{% endif %}
      {% if error %}<div class="error">{{ error }}</div>{% endif %}
      <form method="post">
        {% if show_email_field is not defined or show_email_field %}
          <label for="email">{{ identifier_label or 'Email' }}</label>
          <input id="email" name="email" type="{{ identifier_type or 'email' }}" value="{{ email_value or '' }}" required>
        {% endif %}
        {% if show_password_field is not defined or show_password_field %}
          <label for="password">Password</label>
          <input id="password" name="password" type="password" required>
        {% endif %}
        <button type="submit">{{ submit_label }}</button>
      </form>
      <p class="meta">
        <a class="button" href="{{ url_for('index') }}">Back to domains</a>
      </p>
    </div>
  </body>
</html>
"""




def get_admin_credentials():
    admin_username = (os.environ.get("username") or os.environ.get("ADMIN_USERNAME") or "").strip()
    admin_password = (os.environ.get("user_password") or os.environ.get("ADMIN_PASSWORD") or "").strip()
    return admin_username, admin_password


def normalize_email(email: str) -> str:
    return email.strip().lower()


def get_user_by_email(email: str):
    normalized = normalize_email(email)
    if not normalized:
        return None
    return User.query.filter_by(email=normalized).first()


def get_existing_stripe_customer(email: str):
    normalized = normalize_email(email)
    if not normalized:
        return None

    try:
        customers = stripe.Customer.list(email=normalized, limit=1).get("data", [])
    except stripe.error.StripeError:
        return None
    return customers[0] if customers else None


def stripe_customer_has_active_subscription(customer_id: str) -> bool:
    if not customer_id:
        return False

    try:
        subscriptions = stripe.Subscription.list(customer=customer_id, status="all", limit=10).get("data", [])
    except stripe.error.StripeError:
        return False

    active_statuses = {"active", "trialing", "past_due", "unpaid", "incomplete"}
    return any(subscription.get("status") in active_statuses for subscription in subscriptions)


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


def ensure_database_schema():
    db.create_all()
    with db.engine.begin() as connection:
        connection.execute(db.text("ALTER TABLE domain ADD COLUMN IF NOT EXISTS release_date DATE"))
        connection.execute(db.text("CREATE INDEX IF NOT EXISTS ix_domain_release_date ON domain (release_date)"))
        connection.execute(db.text("UPDATE domain SET release_date = fetch_date WHERE release_date IS NULL"))
        try:
            connection.execute(db.text('ALTER TABLE "user" ALTER COLUMN password_hash DROP NOT NULL'))
        except Exception:
            pass


with app.app_context():
    ensure_database_schema()


@app.route("/")
def index():
    today = datetime.now(timezone.utc).date()
    search_query = request.args.get("q", "").strip().lower()
    try:
        page = max(int(request.args.get("page", "1")), 1)
    except ValueError:
        page = 1
    try:
        requested_page_size = int(request.args.get("page_size", "25"))
    except ValueError:
        requested_page_size = 25
    page_size = requested_page_size if requested_page_size in {10, 25, 50} else 25
    latest_fetch_date = db.session.query(db.func.max(Domain.fetch_date)).scalar()
    latest_release_date = db.session.query(db.func.max(Domain.release_date)).scalar()
    using_live_fallback = False
    try:
        release_date = fetch_release_date()
    except Exception:
        release_date = None

    current_release_date = date.fromisoformat(release_date) if release_date else None
    if current_release_date and Domain.query.filter_by(release_date=current_release_date).first():
        active_date = current_release_date
    elif latest_release_date:
        active_date = latest_release_date
    elif Domain.query.filter_by(fetch_date=today).first():
        active_date = today
    else:
        active_date = latest_fetch_date

    if active_date is None:
        try:
            scraped_domains = scrape_domains()
        except Exception:
            scraped_domains = []

        filtered_scraped_domains = [
            domain for domain in scraped_domains if search_query in domain.lower()
        ] if search_query else scraped_domains
        total_domains = len(scraped_domains)
        total_filtered = len(filtered_scraped_domains)

        if not current_user.is_authenticated or not current_user.is_premium:
            accessible_domains = filtered_scraped_domains[:25]
            is_limited = total_filtered > 25
            total_pages = max(1, (len(accessible_domains) + page_size - 1) // page_size) if accessible_domains else 1
            if page > total_pages:
                page = total_pages
            start_offset = (page - 1) * page_size
            visible_domains = accessible_domains[start_offset:start_offset + page_size]
        else:
            accessible_domains = filtered_scraped_domains
            is_limited = False
            total_pages = 1
            page = 1
            visible_domains = accessible_domains

        domains = [
            SimpleNamespace(
                domain_name=domain,
                da=None,
                linking_root_domains=None,
                release_date=current_release_date or release_date,
            )
            for domain in visible_domains
        ]
        domains = hydrate_visible_domains(domains, today)
        ensure_today_domain_snapshot(scraped_domains, domains, today, current_release_date or today)
        hidden_count = max(total_domains - len(accessible_domains), 0)
        using_live_fallback = bool(scraped_domains)
        if any(domain.da is not None or domain.linking_root_domains is not None for domain in domains):
            active_date = current_release_date or today
            using_live_fallback = False
        highest_authority = max((domain.da or 0) for domain in domains) if domains else 0
        highest_referring_domains = max((domain.linking_root_domains or 0) for domain in domains) if domains else 0
    else:
        base_query = Domain.query.filter(
            (Domain.release_date == active_date) | ((Domain.release_date.is_(None)) & (Domain.fetch_date == active_date))
        ).order_by(
            Domain.da.is_(None), Domain.da.desc(), Domain.domain_name.asc()
        )
        total_domains = base_query.count()
        query = base_query
        if search_query:
            query = query.filter(Domain.domain_name.ilike(f"%{search_query}%"))
        total_filtered = query.count()

        if not current_user.is_authenticated or not current_user.is_premium:
            accessible_domains = query.limit(25).all()
            is_limited = total_filtered > 25
            total_pages = max(1, (len(accessible_domains) + page_size - 1) // page_size) if accessible_domains else 1
            if page > total_pages:
                page = total_pages
            start_offset = (page - 1) * page_size
            domains = accessible_domains[start_offset:start_offset + page_size]
        else:
            total_pages = 1
            page = 1
            domains = query.all()
            is_limited = False

        hidden_count = max(total_domains - min(total_filtered, 25), 0) if not current_user.is_authenticated or not current_user.is_premium else 0
        if any(domain.da is None and domain.linking_root_domains is None for domain in domains):
            domains = hydrate_visible_domains(domains, active_date)
        metric_summary = query.with_entities(
            db.func.max(Domain.da),
            db.func.max(Domain.linking_root_domains),
        ).order_by(None).first()
        highest_authority = metric_summary[0] or 0
        highest_referring_domains = metric_summary[1] or 0

    domains_with_da = [domain.da for domain in domains if domain.da is not None]
    domains_with_links = [domain.linking_root_domains for domain in domains if domain.linking_root_domains is not None]
    dashboard_stats = [
        {
            "label": "Total Domains",
            "value": total_filtered,
            "detail": "Active in current dataset",
        },
        {
            "label": "High Authority",
            "value": highest_authority,
            "detail": "Highest DA today",
        },
        {
            "label": "Referring Domains",
            "value": highest_referring_domains,
            "detail": "Most links to one domain",
        },
    ]
    start_index = ((page - 1) * page_size) + 1 if total_filtered else 0
    end_index = min((page - 1) * page_size + len(domains), total_filtered) if total_filtered else 0

    return render_template(
        "index.html",
        domains=domains,
        is_limited=is_limited,
        total_domains=total_domains,
        total_filtered=total_filtered,
        hidden_count=hidden_count,
        active_date=active_date,
        using_latest_available=active_date is not None and active_date != today,
        using_live_fallback=using_live_fallback,
        release_date=release_date,
        dashboard_stats=dashboard_stats,
        search_query=search_query,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        start_index=start_index,
        end_index=end_index,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    return redirect(url_for("checkout"))


@app.route("/login", methods=["GET", "POST"])
def login():
    checkout_email = normalize_email(request.args.get("email", ""))
    checkout_message = None
    if checkout_email:
        checkout_message = f"Your Stripe checkout used {checkout_email}. Log in to access premium on that account."

    error = None
    if request.method == "POST":
        identifier = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        admin_username, admin_password = get_admin_credentials()

        if admin_username and admin_password and identifier == admin_username and password == admin_password:
            session["is_admin"] = True
            return redirect(url_for("admin"))

        user = get_user_by_email(identifier)
        if user is None or not user.check_password(password):
            error = "Invalid login credentials."
        else:
            login_user(user)
            return redirect(url_for("index"))

    return render_template_string(
        AUTH_TEMPLATE,
        title="Login",
        submit_label="Sign in",
        error=error,
        description=checkout_message,
        identifier_label="Email or username",
        identifier_type="text",
        email_value=checkout_email,
    )


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/user")
@login_required
def user_page():
    return render_template_string(USER_TEMPLATE, user=current_user)


@app.route("/billing")
@login_required
def billing_portal():
    if not current_user.stripe_customer_id:
        return redirect(url_for("user_page"))

    if not get_stripe_secret_key():
        abort(500, "Stripe is not configured. Set STRIPE_SECRET_KEY/Secret_key_test.")

    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=current_user.stripe_customer_id,
            return_url=url_for("user_page", _external=True),
        )
    except stripe.error.StripeError as exc:
        return abort(500, f"Stripe billing portal error: {str(exc)}")

    return redirect(portal_session.url, code=303)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    return redirect(url_for("login"))


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("login"))


@app.route("/admin")
def admin():
    if not session.get("is_admin"):
        return redirect(url_for("login"))

    today = datetime.now(timezone.utc).date()
    try:
        current_release_date_text = fetch_release_date()
        current_release_date = date.fromisoformat(current_release_date_text) if current_release_date_text else today
    except Exception:
        current_release_date = today

    today_rows = Domain.query.filter_by(fetch_date=today).order_by(Domain.da.is_(None), Domain.da.desc(), Domain.domain_name.asc()).all()
    if len(today_rows) <= 25:
        try:
            scraped_domains = scrape_domains()
            ensure_today_domain_snapshot(scraped_domains, today_rows, today, current_release_date or today)
        except Exception:
            pass

    users = User.query.order_by(User.id.desc()).all()
    domains = Domain.query.order_by(Domain.fetch_date.desc(), Domain.da.is_(None), Domain.da.desc(), Domain.domain_name.asc()).all()
    fetch_dates = sorted({row.fetch_date.isoformat() for row in domains if row.fetch_date is not None}, reverse=True)
    total_users = User.query.count()
    premium_users = User.query.filter_by(is_premium=True).count()
    today_domains = Domain.query.filter_by(fetch_date=today).count()
    return render_template_string(
        ADMIN_TEMPLATE,
        users=users,
        domains=domains,
        fetch_dates=fetch_dates,
        total_users=total_users,
        premium_users=premium_users,
        today_domains=today_domains,
    )




@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    if current_user.is_authenticated and current_user.is_premium:
        return redirect(url_for("index"))

    price_id = get_stripe_price_id()
    if not get_stripe_secret_key() or not price_id:
        abort(500, "Stripe is not configured. Set STRIPE_SECRET_KEY/Secret_key_test and STRIPE_PRICE_ID/STRIPE_PRICE_ID_TEST.")

    checkout_kwargs = {
        "mode": "subscription",
        "line_items": [{"price": price_id, "quantity": 1}],
        "success_url": url_for("complete_setup", _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
        "cancel_url": url_for("index", _external=True),
    }

    if current_user.is_authenticated:
        checkout_email = normalize_email(current_user.email)
        checkout_kwargs["client_reference_id"] = str(current_user.id)
        if current_user.stripe_customer_id:
            checkout_kwargs["customer"] = current_user.stripe_customer_id
        else:
            checkout_kwargs["customer_email"] = checkout_email

    try:
        checkout_session = stripe.checkout.Session.create(**checkout_kwargs)
    except stripe.error.StripeError as exc:
        return abort(500, f"Stripe checkout error: {str(exc)}. Make sure the price ID matches the configured Stripe key and test/live mode.")

    return redirect(checkout_session.url, code=303)


@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_data(as_text=False)
    signature = request.headers.get("Stripe-Signature", "")
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

    try:
        if webhook_secret:
            event = stripe.Webhook.construct_event(payload, signature, webhook_secret)
        else:
            event = request.get_json(force=True)
    except Exception as exc:
        return {"error": str(exc)}, 400

    if event.get("type") == "checkout.session.completed":
        session = event["data"]["object"]
        user = None

        client_reference_id = session.get("client_reference_id")
        if client_reference_id and str(client_reference_id).isdigit():
            user = db.session.get(User, int(client_reference_id))

        if user is None:
            email = (
                (session.get("customer_details") or {}).get("email")
                or session.get("customer_email")
            )
            if email:
                email = normalize_email(email)
                user = get_user_by_email(email)

                if user is None:
                    user = User(email=email)
                    db.session.add(user)

        if user is not None:
            session_customer_id = session.get("customer")
            if user.stripe_customer_id and session_customer_id and user.stripe_customer_id != session_customer_id:
                return {"status": "ignored_duplicate_checkout"}, 200
            user.is_premium = True
            user.stripe_customer_id = session_customer_id or user.stripe_customer_id
            db.session.commit()

    return {"status": "ok"}, 200


@app.route("/complete_setup", methods=["GET", "POST"])
def complete_setup():
    session_id = request.args.get("session_id")
    if not session_id:
        return redirect(url_for("index"))

    try:
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        email = (checkout_session.get("customer_details") or {}).get("email")
        if not email:
            return abort(400, "Could not verify email from Stripe.")
        email = normalize_email(email)
    except Exception as e:
        return abort(400, f"Session error: {str(e)}")

    session_customer_id = checkout_session.get("customer")
    user = get_user_by_email(email)
    existing_account = bool(user and user.password_hash)
    error = None

    if user is not None and session_customer_id and not user.stripe_customer_id:
        user.stripe_customer_id = session_customer_id
        user.is_premium = True
        db.session.commit()
    elif user is not None and session_customer_id and user.stripe_customer_id == session_customer_id and not user.is_premium:
        user.is_premium = True
        db.session.commit()

    if existing_account:
        if user.stripe_customer_id and session_customer_id and user.stripe_customer_id != session_customer_id:
            error = "This email is already linked to a different payment profile. Please log in to the existing account instead."
        else:
            return redirect(url_for("login", email=email))

    if request.method == "POST":
        password = request.form.get("password", "")
        if not password:
            error = "Please enter a password."
        else:
            if user is None:
                user = User(email=email)
                db.session.add(user)

            if user.stripe_customer_id and session_customer_id and user.stripe_customer_id != session_customer_id:
                error = "This email is already linked to a different payment profile. Please log in to the existing account instead."
                return render_template_string(SETUP_TEMPLATE, email=email, error=error, existing_account=existing_account)

            user.set_password(password)
            user.is_premium = True
            user.stripe_customer_id = session_customer_id or user.stripe_customer_id
            db.session.commit()
            login_user(user)
            return redirect(url_for("index"))

    SETUP_TEMPLATE = """
    <!doctype html>
    <html lang="en">
      <head><title>Complete Setup</title><style>body { font-family: Arial; background: #f4f7fb; padding: 32px; } .card { max-width: 420px; margin: 0 auto; background: #fff; padding: 24px; border-radius: 12px; } input { width: 100%; padding: 12px; margin: 8px 0 14px; border: 1px solid #d1d5db; border-radius: 8px; box-sizing: border-box; } button, a.button { display: inline-block; background: #111827; color: #fff; padding: 12px 16px; border-radius: 8px; border: 0; cursor: pointer; text-decoration: none; } .error { margin-bottom: 14px; color: #b91c1c; }</style></head>
      <body>
        <div class="card">
          <h1>Welcome!</h1>
          {% if existing_account %}
            <p>Your payment was successful for <strong>{{ email }}</strong>. Log in to your existing account to access premium.</p>
            {% if error %}<div class="error">{{ error }}</div>{% endif %}
            <a class="button" href="{{ url_for('login', email=email) }}">Go to Login</a>
          {% else %}
            <p>Your payment was successful. Please set a password for <strong>{{ email }}</strong> to complete your account.</p>
            {% if error %}<div class="error">{{ error }}</div>{% endif %}
            <form method="post">
              <label>Password</label>
              <input name="password" type="password" required>
              <button type="submit">Complete Setup</button>
            </form>
          {% endif %}
        </div>
      </body>
    </html>
    """
    return render_template_string(SETUP_TEMPLATE, email=email, error=error, existing_account=existing_account)


if __name__ == "__main__":
    app.run(debug=True)
