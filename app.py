import os
import re
from datetime import datetime, timezone
from types import SimpleNamespace

import requests
import stripe
from bs4 import BeautifulSoup
from flask import Flask, abort, redirect, render_template, render_template_string, request, session, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from requests.auth import HTTPBasicAuth

from models import Domain, User, db

SOURCE_URL = "https://www.rymdweb.com/domain/snapback/?action=date"
MOZ_API_URL = "https://lsapi.seomoz.com/v2/url_metrics"
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9,sv;q=0.8",
}
DOMAIN_PATTERN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:se|nu)\b", re.IGNORECASE)
RELEASE_DATE_PATTERN = re.compile(r"Domäner som släpps\s+(\d{4}-\d{2}-\d{2})", re.IGNORECASE)


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

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")




def fetch_release_date():
    response = requests.get(SOURCE_URL, headers=REQUEST_HEADERS, timeout=20)
    response.raise_for_status()

    text = response.text
    match = RELEASE_DATE_PATTERN.search(text)
    if match:
        return match.group(1)

    soup = BeautifulSoup(text, "html.parser")
    page_text = soup.get_text(" ", strip=True)
    match = RELEASE_DATE_PATTERN.search(page_text)
    return match.group(1) if match else None


def scrape_domains(limit: int | None = None):
    response = requests.get(SOURCE_URL, headers=REQUEST_HEADERS, timeout=20)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")
    extracted = []
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
        candidate = requests.post(
            MOZ_API_URL,
            json={"targets": moz_targets},
            timeout=30,
            **auth_kwargs,
        )
        if candidate.ok:
            response = candidate
            break
        if candidate.status_code not in (401, 403):
            candidate.raise_for_status()

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



USER_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>User Page</title>
    <style>
      body { font-family: Arial, sans-serif; background: #f4f7fb; padding: 32px; color: #1f2937; }
      .card { max-width: 720px; margin: 0 auto; background: #fff; padding: 24px; border-radius: 12px; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08); }
      .row { margin-bottom: 14px; }
      .label { font-weight: bold; }
      a.button { display: inline-block; background: #111827; color: #fff; padding: 12px 16px; border-radius: 8px; text-decoration: none; margin-right: 12px; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>User Page</h1>
      <div class="row"><span class="label">Email:</span> {{ user.email }}</div>
      <div class="row"><span class="label">Premium:</span> {{ 'Yes' if user.is_premium else 'No' }}</div>
      <div class="row"><span class="label">Stripe customer:</span> {{ user.stripe_customer_id or 'Not connected yet' }}</div>
      <div class="row">
        {% if not user.is_premium %}
          <a class="button" href="{{ url_for('checkout') }}">Upgrade to Premium</a>
        {% endif %}
        <a class="button" href="{{ url_for('index') }}">Back to domains</a>
      </div>
    </div>
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
      body { font-family: Arial, sans-serif; background: #f4f7fb; padding: 32px; color: #1f2937; }
      .card { max-width: 420px; margin: 0 auto; background: #fff; padding: 24px; border-radius: 12px; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08); }
      input { width: 100%; padding: 12px; margin: 8px 0 14px; border: 1px solid #d1d5db; border-radius: 8px; box-sizing: border-box; }
      button, a.button { display: inline-block; background: #111827; color: #fff; padding: 12px 16px; border-radius: 8px; text-decoration: none; border: 0; cursor: pointer; }
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
      body { font-family: Arial, sans-serif; background: #f4f7fb; padding: 32px; color: #1f2937; }
      .card { max-width: 1100px; margin: 0 auto; background: #fff; padding: 24px; border-radius: 12px; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08); }
      .stats { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
      .stat { background: #f9fafb; padding: 16px; border-radius: 10px; min-width: 180px; }
      table { width: 100%; border-collapse: collapse; margin-top: 16px; }
      th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #e5e7eb; }
      th { background: #111827; color: #fff; }
      a.button { display: inline-block; background: #111827; color: #fff; padding: 12px 16px; border-radius: 8px; text-decoration: none; margin-right: 12px; }
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
      <table>
        <thead>
          <tr><th>Domain</th><th>DA</th><th>Linking Root Domains</th><th>Fetch Date</th></tr>
        </thead>
        <tbody>
          {% for domain in domains %}
            <tr>
              <td>{{ domain.domain_name }}</td>
              <td>{{ domain.da if domain.da is not none else 'N/A' }}</td>
              <td>{{ domain.linking_root_domains if domain.linking_root_domains is not none else 'N/A' }}</td>
              <td>{{ domain.fetch_date }}</td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
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
      body { font-family: Arial, sans-serif; background: #f4f7fb; padding: 32px; color: #1f2937; }
      .card { max-width: 420px; margin: 0 auto; background: #fff; padding: 24px; border-radius: 12px; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08); }
      input { width: 100%; padding: 12px; margin: 8px 0 14px; border: 1px solid #d1d5db; border-radius: 8px; box-sizing: border-box; }
      button, a.button { display: inline-block; background: #111827; color: #fff; padding: 12px 16px; border-radius: 8px; text-decoration: none; border: 0; cursor: pointer; }
      .error { margin-bottom: 14px; color: #b91c1c; }
      .meta { margin-top: 16px; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>{{ title }}</h1>
      {% if error %}<div class="error">{{ error }}</div>{% endif %}
      <form method="post">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" required>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" required>
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

@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


with app.app_context():
    db.create_all()


@app.route("/")
def index():
    today = datetime.now(timezone.utc).date()
    latest_fetch_date = db.session.query(db.func.max(Domain.fetch_date)).scalar()
    active_date = today if Domain.query.filter_by(fetch_date=today).first() else latest_fetch_date
    using_live_fallback = False
    try:
        release_date = fetch_release_date()
    except Exception:
        release_date = None

    if active_date is None:
        try:
            scraped_domains = scrape_domains()
        except Exception:
            scraped_domains = []

        total_domains = len(scraped_domains)
        if not current_user.is_authenticated or not current_user.is_premium:
            visible_domains = scraped_domains[:25]
            is_limited = total_domains > 25
        else:
            visible_domains = scraped_domains
            is_limited = False

        domains = [
            SimpleNamespace(domain_name=domain, da=None, linking_root_domains=None)
            for domain in visible_domains
        ]
        domains = hydrate_visible_domains(domains, today)
        hidden_count = max(total_domains - len(domains), 0)
        using_live_fallback = bool(scraped_domains)
        if any(domain.da is not None or domain.linking_root_domains is not None for domain in domains):
            active_date = today
            using_live_fallback = False
    else:
        query = Domain.query.filter_by(fetch_date=active_date).order_by(
            Domain.da.is_(None), Domain.da.desc(), Domain.domain_name.asc()
        )
        total_domains = query.count()

        if not current_user.is_authenticated or not current_user.is_premium:
            domains = query.limit(25).all()
            is_limited = total_domains > 25
        else:
            domains = query.all()
            is_limited = False

        hidden_count = max(total_domains - len(domains), 0)
        if any(domain.da is None and domain.linking_root_domains is None for domain in domains):
            domains = hydrate_visible_domains(domains, active_date)

    return render_template(
        "index.html",
        domains=domains,
        is_limited=is_limited,
        total_domains=total_domains,
        hidden_count=hidden_count,
        active_date=active_date,
        using_latest_available=active_date is not None and active_date != today,
        using_live_fallback=using_live_fallback,
        release_date=release_date,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            error = "Email and password are required."
        elif User.query.filter_by(email=email).first():
            error = "An account with that email already exists."
        else:
            user = User(email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for("index"))

    return render_template_string(AUTH_TEMPLATE, title="Register", submit_label="Create account", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user is None or not user.check_password(password):
            error = "Invalid email or password."
        else:
            login_user(user)
            return redirect(url_for("index"))

    return render_template_string(AUTH_TEMPLATE, title="Login", submit_label="Sign in", error=error)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/user")
@login_required
def user_page():
    return render_template_string(USER_TEMPLATE, user=current_user)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        submitted_username = request.form.get("username", "").strip()
        submitted_password = request.form.get("password", "")
        admin_username, admin_password = get_admin_credentials()

        if not admin_username or not admin_password:
            error = "Admin credentials are not configured in Heroku."
        elif submitted_username == admin_username and submitted_password == admin_password:
            session["is_admin"] = True
            return redirect(url_for("admin"))
        else:
            error = "Invalid admin credentials."

    return render_template_string(ADMIN_LOGIN_TEMPLATE, error=error)


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


@app.route("/admin")
def admin():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))

    today = datetime.now(timezone.utc).date()
    users = User.query.order_by(User.id.desc()).all()
    domains = Domain.query.order_by(Domain.fetch_date.desc(), Domain.da.is_(None), Domain.da.desc(), Domain.domain_name.asc()).limit(100).all()
    total_users = User.query.count()
    premium_users = User.query.filter_by(is_premium=True).count()
    today_domains = Domain.query.filter_by(fetch_date=today).count()
    return render_template_string(
        ADMIN_TEMPLATE,
        users=users,
        domains=domains,
        total_users=total_users,
        premium_users=premium_users,
        today_domains=today_domains,
    )




@app.route("/checkout")
@login_required
def checkout():
    if current_user.is_premium:
        return redirect(url_for("index"))

    price_id = os.environ.get("STRIPE_PRICE_ID", "")
    if not stripe.api_key or not price_id:
        abort(500, "Stripe is not configured. Set STRIPE_SECRET_KEY and STRIPE_PRICE_ID.")

    checkout_session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=url_for("index", _external=True) + "?checkout=success",
        cancel_url=url_for("index", _external=True),
        client_reference_id=str(current_user.id),
        customer_email=current_user.email,
        metadata={"user_id": str(current_user.id)},
    )
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
                user = User.query.filter_by(email=email.lower()).first()

        if user is not None:
            user.is_premium = True
            user.stripe_customer_id = session.get("customer")
            db.session.commit()

    return {"status": "ok"}, 200


if __name__ == "__main__":
    app.run(debug=True)
