from __future__ import annotations

import os
import subprocess
from pathlib import Path

from flask import Flask, flash, jsonify, redirect, render_template, request, send_file, session, url_for

from .models import PublishRuleInput
from .nginx_discovery import (
    attach_assigned_urls,
    discover_nginx_bindings,
    discover_nginx_server_names,
    infer_base_domains,
)
from .services import ServiceContainer


def create_app() -> Flask:
    project_root = Path(__file__).resolve().parent.parent
    services = ServiceContainer(project_root)
    services.ensure_layout()
    services.openvpn.load_defaults()

    app = Flask(__name__)
    app.config["SECRET_KEY"] = _required_environment("VPS_TUNNEL_TOOL_SECRET")
    app.config["SERVICES"] = services
    app.config["APP_LOGIN_USER"] = _required_environment("VPS_TUNNEL_TOOL_APP_USER")
    app.config["APP_LOGIN_PASSWORD"] = _required_environment("VPS_TUNNEL_TOOL_APP_PASSWORD")
    configured_domains = os.environ.get(
        "VPS_TUNNEL_TOOL_PUBLIC_DOMAINS",
        os.environ.get("VPS_TUNNEL_TOOL_PUBLIC_DOMAIN", "example.com"),
    )
    app.config["PUBLIC_BASE_DOMAINS"] = [
        domain.strip() for domain in configured_domains.split(",") if domain.strip()
    ]

    @app.before_request
    def require_app_login():
        allowed_endpoints = {"app_login", "app_login_submit", "favicon", "static"}
        if request.endpoint in allowed_endpoints:
            return None
        if session.get("app_authenticated"):
            return None
        next_url = request.full_path if request.query_string else request.path
        return redirect(url_for("app_login", next=next_url))

    @app.get("/")
    def index():
        return redirect(url_for("dashboard"))

    @app.get("/favicon.ico")
    def favicon():
        return send_file(project_root / "app" / "static" / "favicon.svg", mimetype="image/svg+xml")

    @app.get("/app-login")
    def app_login():
        if session.get("app_authenticated"):
            return redirect(url_for("dashboard"))
        return render_template("app_login.html", page_title="アプリ認証", next_url=request.args.get("next", ""))

    @app.post("/app-login")
    def app_login_submit():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.form.get("next_url", "").strip()
        if username == app.config["APP_LOGIN_USER"] and password == app.config["APP_LOGIN_PASSWORD"]:
            session.clear()
            session["app_authenticated"] = True
            session["app_login_user"] = username
            return redirect(next_url or url_for("dashboard"))
        flash("アプリ認証に失敗しました。", "error")
        return render_template("app_login.html", page_title="アプリ認証", next_url=next_url)

    @app.post("/logout")
    def logout():
        session.clear()
        flash("アプリ認証からログアウトしました。", "success")
        return redirect(url_for("app_login"))

    @app.get("/dashboard")
    def dashboard():
        context = _build_page_context(services)
        return render_template("dashboard.html", page_title="ダッシュボード", current_page="dashboard", **context)

    @app.get("/vpn-settings")
    def vpn_settings_page():
        context = _build_page_context(services)
        return render_template("vpn_settings.html", page_title="VPN 設定", current_page="vpn-settings", **context)

    @app.get("/clients")
    def clients_page():
        context = _build_page_context(services)
        return render_template("clients.html", page_title="クライアント", current_page="clients", **context)

    @app.get("/rules")
    def rules_page():
        context = _build_page_context(services)
        bindings = discover_nginx_bindings()
        attach_assigned_urls(
            context["rules"],
            bindings,
            context["settings"].get("remote_host", ""),
        )
        context["assigned_url_rule_count"] = sum(
            1 for rule in context["rules"] if rule["assigned_urls"]
        )
        context["public_base_domains"] = infer_base_domains(
            discover_nginx_server_names(),
            app.config["PUBLIC_BASE_DOMAINS"],
        )
        return render_template("rules.html", page_title="公開ルール", current_page="rules", **context)

    @app.get("/logs")
    def logs_page():
        context = _build_page_context(services)
        context["log_sections"] = _collect_log_sections()
        return render_template("logs.html", page_title="ログ", current_page="logs", **context)

    @app.get("/system")
    def system_page():
        context = _build_page_context(services)
        return render_template("system.html", page_title="設定", current_page="system", **context)

    @app.post("/settings")
    def save_settings():
        for key in ["remote_host", "remote_port", "protocol", "cipher", "auth", "vpn_interface"]:
            services.repository.upsert_setting(key, request.form.get(key, "").strip())
        flash("OpenVPN profile settings updated.", "success")
        return _redirect_back("vpn_settings_page")

    @app.post("/clients")
    def create_client():
        name = request.form.get("name", "").strip()
        try:
            export_path = services.openvpn.create_client(name)
            flash(f"Created client profile: {export_path.name}", "success")
        except Exception as exc:
            flash(str(exc), "error")
        return _redirect_back("clients_page")

    @app.get("/clients/<int:client_id>/download")
    def download_client(client_id: int):
        client = services.repository.get_vpn_client(client_id)
        if not client:
            flash("Client not found.", "error")
            return redirect(url_for("clients_page"))
        return send_file(client["export_path"], as_attachment=True)

    @app.post("/rules")
    def create_rule():
        try:
            normalized = services.publisher.validate_rule(
                name=request.form.get("name", ""),
                protocol=request.form.get("protocol", "tcp"),
                public_bind_ip=request.form.get("public_bind_ip", "0.0.0.0"),
                public_port=_parse_optional_int(request.form.get("public_port", "")),
                target_ip=request.form.get("target_ip", ""),
                target_port=int(request.form.get("target_port", "0")),
            )
            services.repository.add_publish_rule(PublishRuleInput(**normalized))
            flash(f"Publish rule added. public port: {normalized['public_port']}", "success")
        except Exception as exc:
            flash(str(exc), "error")
        return _redirect_back("rules_page")

    @app.post("/rules/<int:rule_id>/toggle")
    def toggle_rule(rule_id: int):
        services.repository.toggle_publish_rule(rule_id)
        flash("Rule status updated.", "success")
        return _redirect_back("rules_page")

    @app.post("/rules/<int:rule_id>/delete")
    def delete_rule(rule_id: int):
        services.repository.delete_publish_rule(rule_id)
        flash("Rule deleted.", "success")
        return _redirect_back("rules_page")

    @app.post("/rules/<int:rule_id>/assign-url")
    def assign_rule_url(rule_id: int):
        rule = services.repository.get_publish_rule(rule_id)
        if not rule:
            return jsonify({"ok": False, "message": "公開ルールが見つかりません。"}), 404

        try:
            result = services.nginx_urls.assign(
                rule=rule,
                subdomain=request.form.get("subdomain", ""),
                base_domain=(
                    request.form.get("custom_base_domain", "")
                    if request.form.get("base_domain") == "__custom__"
                    else request.form.get("base_domain", "")
                ),
                public_host=services.repository.get_settings().get("remote_host", ""),
                enable_https=request.form.get("enable_https") == "1",
            )
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            return jsonify({"ok": False, "message": str(exc)}), 400

        return jsonify({"ok": True, **result})

    @app.post("/rules/<int:rule_id>/enable-https")
    def enable_rule_https(rule_id: int):
        rule = services.repository.get_publish_rule(rule_id)
        if not rule:
            return jsonify({"ok": False, "message": "公開ルールが見つかりません。"}), 404

        try:
            result = services.nginx_urls.enable_https(
                rule=rule,
                hostname=request.form.get("hostname", ""),
                public_host=services.repository.get_settings().get("remote_host", ""),
            )
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            return jsonify({"ok": False, "message": str(exc)}), 400

        return jsonify({"ok": True, **result})

    @app.post("/apply")
    def apply_rules():
        try:
            output_path = services.publisher.apply()
            flash(f"Applied nftables rules: {output_path}", "success")
        except Exception as exc:
            flash(str(exc), "error")
        return _redirect_back("system_page")

    @app.post("/install-systemd")
    def install_systemd():
        try:
            service_path = services.publisher.install_systemd_unit("python3", project_root)
            flash(f"Installed systemd unit: {service_path}", "success")
        except Exception as exc:
            flash(str(exc), "error")
        return _redirect_back("system_page")

    @app.post("/install-web-systemd")
    def install_web_systemd():
        try:
            service_path = services.publisher.install_web_systemd_unit("python3", project_root, "127.0.0.1", 5000)
            flash(f"Installed web systemd unit: {service_path}", "success")
        except Exception as exc:
            flash(str(exc), "error")
        return _redirect_back("system_page")

    def _redirect_back(default_endpoint: str):
        target = request.headers.get("Referer")
        if target:
            return redirect(target)
        return redirect(url_for(default_endpoint))

    return app


def _build_page_context(services: ServiceContainer) -> dict:
        repository = services.repository
        settings = repository.get_settings()
        clients = repository.list_vpn_clients()
        rules = repository.list_publish_rules()
        default_public_bind_ip = "0.0.0.0"
        try:
            suggested_public_port = services.publisher.find_available_public_port("tcp", default_public_bind_ip)
        except ValueError:
            suggested_public_port = ""
        applied_rules_path = services.paths.generated_dir / "vps-tunnel-tool.nft"
        active_rule_count = sum(1 for rule in rules if rule["enabled"])
        return {
            "settings": settings,
            "clients": clients,
            "rules": rules,
            "default_public_bind_ip": default_public_bind_ip,
            "suggested_public_port": suggested_public_port,
            "applied_rules_path": applied_rules_path,
            "applied_rules_exists": applied_rules_path.exists(),
            "active_rule_count": active_rule_count,
            "service_statuses": _collect_service_statuses(),
        }


def _collect_service_statuses() -> list[dict]:
    services = [
        ("OpenVPN", "openvpn-server@server.service"),
        ("WebUI", "vps-tunnel-tool-web.service"),
        ("自動反映", "vps-tunnel-tool-apply.service"),
    ]
    return [
        {
            "label": label,
            "unit": unit,
            "state": _systemctl_value("is-active", unit, default="unknown"),
            "enabled": _systemctl_value("is-enabled", unit, default="unknown"),
            "active": _systemctl_value("is-active", unit, default="inactive") == "active",
        }
        for label, unit in services
    ]


def _collect_log_sections() -> list[dict]:
    sections = []
    for label, unit in [
        ("WebUI", "vps-tunnel-tool-web.service"),
        ("自動反映", "vps-tunnel-tool-apply.service"),
        ("OpenVPN", "openvpn-server@server.service"),
    ]:
        result = subprocess.run(
            ["journalctl", "-u", unit, "-n", "20", "--no-pager", "-o", "short-iso"],
            check=False,
            capture_output=True,
            text=True,
        )
        lines = [line for line in result.stdout.splitlines() if line.strip()] if result.returncode == 0 else []
        sections.append({"label": label, "unit": unit, "lines": lines})
    return sections


def _systemctl_value(command: str, unit: str, default: str) -> str:
    result = subprocess.run(
        ["systemctl", command, unit],
        check=False,
        capture_output=True,
        text=True,
    )
    value = (result.stdout or result.stderr).strip().splitlines()
    return value[0] if value else default


def _parse_optional_int(value: str) -> int | None:
    stripped = value.strip()
    if not stripped:
        return None
    return int(stripped)


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"required environment variable is not set: {name}")
    return value
