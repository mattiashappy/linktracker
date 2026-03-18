import os
from datetime import datetime, timezone

import stripe
from flask import Flask, abort, redirect, render_template, render_template_string, request, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user

from models import Domain, User, db


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


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


with app.app_context():
    db.create_all()


@app.route("/")
def index():
    today = datetime.now(timezone.utc).date()
    query = Domain.query.filter_by(fetch_date=today).order_by(Domain.da.is_(None), Domain.da.desc(), Domain.domain_name.asc())
    total_domains = query.count()

    if not current_user.is_authenticated or not current_user.is_premium:
        domains = query.limit(25).all()
        is_limited = total_domains > 25
    else:
        domains = query.all()
        is_limited = False

    hidden_count = max(total_domains - len(domains), 0)
    return render_template(
        "index.html",
        domains=domains,
        is_limited=is_limited,
        total_domains=total_domains,
        hidden_count=hidden_count,
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
