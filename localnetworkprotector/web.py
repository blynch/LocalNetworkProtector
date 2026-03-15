import json
import logging
from functools import wraps

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

log = logging.getLogger(__name__)


def create_app(config, db_manager, monitor_service):
    app = Flask(__name__)
    app.secret_key = config.web.session_secret or "dev-secret-key-change-in-prod"

    @app.template_filter("json_load")
    def json_load_filter(s):
        if not s:
            return {}
        try:
            return json.loads(s)
        except Exception:
            return {}

    def auth_enabled() -> bool:
        return bool(config.web.auth_enabled)

    def is_authenticated() -> bool:
        return bool(session.get("authenticated"))

    def verify_credentials(username: str, password: str) -> bool:
        if username != config.web.username:
            return False
        if config.web.password_hash:
            return check_password_hash(config.web.password_hash, password)
        if config.web.password is not None:
            return password == config.web.password
        return False

    def configured_api_tokens() -> set[str]:
        return {token for token in config.web.api_tokens if token}

    def api_token_is_valid() -> bool:
        tokens = configured_api_tokens()
        if not tokens:
            return False
        header_value = request.headers.get("Authorization", "")
        if header_value.startswith("Bearer "):
            token = header_value[7:].strip()
            if token in tokens:
                return True
        api_key = request.headers.get("X-API-Key", "").strip()
        return api_key in tokens if api_key else False

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if auth_enabled() and not is_authenticated():
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)

        return wrapped

    def api_auth_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if api_token_is_valid():
                return view(*args, **kwargs)
            if not configured_api_tokens() and (not auth_enabled() or is_authenticated()):
                return view(*args, **kwargs)
            if auth_enabled() and is_authenticated():
                return view(*args, **kwargs)
            return jsonify({"error": "unauthorized"}), 401

        return wrapped

    def get_positive_int(param: str, default: int, maximum: int = 200) -> int:
        try:
            return max(1, min(int(request.args.get(param, str(default))), maximum))
        except ValueError:
            return default

    @app.context_processor
    def inject_auth_state():
        return {
            "auth_enabled": auth_enabled(),
            "is_authenticated": is_authenticated(),
        }

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not auth_enabled():
            return redirect(url_for("index"))
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if verify_credentials(username, password):
                session["authenticated"] = True
                session["username"] = username
                flash("Signed in successfully.", "success")
                next_url = request.args.get("next") or url_for("index")
                return redirect(next_url)
            flash("Invalid username or password.", "danger")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        session.clear()
        flash("Signed out.", "success")
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def index():
        stats = db_manager.get_dashboard_stats()
        recent_alerts = db_manager.get_recent_findings(limit=5)
        return render_template(
            "index.html",
            device_count=stats["device_count"],
            scan_count=stats["scan_count"],
            tsunami_count=stats["tsunami_count"],
            recent_alerts=recent_alerts,
        )

    @app.route("/devices")
    @login_required
    def devices():
        return render_template("devices.html", devices=db_manager.get_eero_devices())

    @app.route("/scans")
    @login_required
    def scans():
        status = request.args.get("status") or None
        page = get_positive_int("page", 1, 10000)
        per_page = get_positive_int("per_page", 25, 100)
        result = db_manager.get_scan_history_page(page=page, per_page=per_page, status=status)
        return render_template(
            "scans.html",
            scans=result["items"],
            pagination=result,
            selected_status=status or "",
            per_page=per_page,
        )

    @app.route("/scans/<int:scan_id>")
    @login_required
    def scan_details(scan_id: int):
        findings_page = get_positive_int("findings_page", 1, 10000)
        findings_per_page = get_positive_int("findings_per_page", 25, 100)
        scan = db_manager.get_scan_details(
            scan_id,
            findings_page=findings_page,
            findings_per_page=findings_per_page,
        )
        if scan is None:
            flash(f"Scan #{scan_id} was not found.", "warning")
            return redirect(url_for("scans"))
        return render_template(
            "scan_detail.html",
            scan=scan,
            findings_pagination=scan["findings_page"],
            findings_per_page=findings_per_page,
        )

    @app.route("/api/scans")
    @api_auth_required
    def scans_api():
        status = request.args.get("status") or None
        page = get_positive_int("page", 1, 10000)
        per_page = get_positive_int("per_page", 25, 100)
        return jsonify(
            db_manager.get_scan_history_page(page=page, per_page=per_page, status=status)
        )

    @app.route("/api/scans/<int:scan_id>")
    @api_auth_required
    def scan_detail_api(scan_id: int):
        findings_page = get_positive_int("findings_page", 1, 10000)
        findings_per_page = get_positive_int("findings_per_page", 25, 100)
        scan = db_manager.get_scan_details(
            scan_id,
            findings_page=findings_page,
            findings_per_page=findings_per_page,
        )
        if scan is None:
            return jsonify({"error": "not_found", "scan_id": scan_id}), 404
        return jsonify(scan)

    @app.route("/tsunami")
    @login_required
    def tsunami():
        findings = db_manager.get_tsunami_findings()
        return render_template("tsunami.html", findings=findings)

    @app.route("/scan/trigger", methods=["POST"])
    @login_required
    def trigger_scan():
        ip = request.form.get("ip", "")
        if not monitor_service:
            flash("Monitor service unavailable.", "danger")
            return redirect(url_for("devices"))

        accepted, message = monitor_service.request_scan(ip, source="manual")
        if accepted:
            flash(f"Scan initiated for {ip}.", "success")
        else:
            flash(f"Scan not started for {ip}: {message}", "warning")
        return redirect(url_for("devices"))

    return app
