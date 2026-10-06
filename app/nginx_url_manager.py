from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from .nginx_discovery import discover_nginx_bindings


class NginxUrlManager:
    SUBDOMAIN_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    DOMAIN_PATTERN = re.compile(
        r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    def __init__(
        self,
        sites_available: Path = Path("/etc/nginx/sites-available"),
        sites_enabled: Path = Path("/etc/nginx/sites-enabled"),
    ) -> None:
        self.sites_available = sites_available
        self.sites_enabled = sites_enabled

    def assign(
        self,
        rule: dict,
        subdomain: str,
        base_domain: str,
        public_host: str,
        enable_https: bool,
    ) -> dict:
        if rule["protocol"] != "tcp":
            raise ValueError("URLを割り当てられるのは TCP ルールだけです。")

        clean_subdomain = subdomain.strip().lower()
        if not self.SUBDOMAIN_PATTERN.fullmatch(clean_subdomain):
            raise ValueError("サブドメインは英小文字・数字・ハイフンで入力してください。")

        clean_base_domain = base_domain.strip().lower().strip(".")
        if not self.DOMAIN_PATTERN.fullmatch(clean_base_domain):
            raise ValueError("メインドメインの形式が不正です。")
        hostname = f"{clean_subdomain}.{clean_base_domain}"
        if len(hostname) > 253:
            raise ValueError("割り当てるホスト名が長すぎます。")
        target_ip = str(ipaddress.ip_address(rule["target_ip"]))
        target_port = int(rule["target_port"])
        if target_port < 1 or target_port > 65535:
            raise ValueError("VPN先ポートが不正です。")

        self._ensure_hostname_is_available(hostname, target_ip, target_port)
        self._ensure_http_site(hostname, target_ip, target_port)

        dns_ips = self._resolve_ipv4(hostname)
        expected_ips = self._resolve_ipv4(public_host)
        dns_ready = bool(dns_ips & expected_ips)
        https_enabled = self._has_https_binding(hostname)
        warning = ""

        if enable_https and not https_enabled:
            if dns_ready:
                try:
                    self._enable_https(hostname)
                    https_enabled = self._has_https_binding(hostname)
                except RuntimeError as exc:
                    warning = f"HTTP割り当ては完了しましたが、HTTPS化に失敗しました: {exc}"
            else:
                warning = (
                    "HTTP割り当ては完了しました。HTTPS化するには、"
                    f"{hostname} の A レコードを {public_host} に向けてから再実行してください。"
                )

        scheme = "https" if https_enabled else "http"
        return {
            "hostname": hostname,
            "url": f"{scheme}://{hostname}/",
            "https_enabled": https_enabled,
            "dns_ready": dns_ready,
            "dns_ips": sorted(dns_ips),
            "expected_ips": sorted(expected_ips),
            "warning": warning,
        }

    def enable_https(self, rule: dict, hostname: str, public_host: str) -> dict:
        if rule["protocol"] != "tcp":
            raise ValueError("HTTPS化できるのは TCP ルールだけです。")

        clean_hostname = hostname.strip().lower().strip(".")
        if not self.DOMAIN_PATTERN.fullmatch(clean_hostname):
            raise ValueError("ホスト名の形式が不正です。")

        target_ip = str(ipaddress.ip_address(rule["target_ip"]))
        target_port = int(rule["target_port"])
        hostname_bindings = self._hostname_bindings(clean_hostname)
        if not hostname_bindings:
            raise ValueError(f"{clean_hostname} の有効な nginx 設定が見つかりません。")
        if any(
            binding["target_host"] != target_ip or binding["target_port"] != target_port
            for binding in hostname_bindings
        ):
            raise ValueError(f"{clean_hostname} はこの公開ルールの転送先と一致しません。")

        dns_ips = self._resolve_ipv4(clean_hostname)
        expected_ips = self._resolve_ipv4(public_host)
        if not dns_ips or not (dns_ips & expected_ips):
            resolved = ", ".join(sorted(dns_ips)) if dns_ips else "未設定"
            raise ValueError(
                f"DNSが未反映です。{clean_hostname} の A レコードを {public_host} に設定してください。"
                f" 現在の解決先: {resolved}"
            )

        if not self._has_https_binding(clean_hostname):
            self._enable_https(clean_hostname)
        if not self._has_https_binding(clean_hostname):
            raise RuntimeError("証明書発行後もHTTPS設定を確認できませんでした。")

        return {
            "hostname": clean_hostname,
            "url": f"https://{clean_hostname}/",
            "https_enabled": True,
            "dns_ready": True,
            "dns_ips": sorted(dns_ips),
            "expected_ips": sorted(expected_ips),
            "warning": "",
        }

    def _ensure_hostname_is_available(self, hostname: str, target_ip: str, target_port: int) -> None:
        hostname_bindings = self._hostname_bindings(hostname)
        if not hostname_bindings:
            available_path = self.sites_available / hostname
            if available_path.exists():
                raise ValueError(f"既存の nginx 設定と競合しています: {available_path}")
            return

        if any(
            binding["target_host"] != target_ip or binding["target_port"] != target_port
            for binding in hostname_bindings
        ):
            raise ValueError(f"{hostname} は別の転送先に割り当て済みです。")

    def _hostname_bindings(self, hostname: str) -> list[dict]:
        return [
            binding
            for binding in discover_nginx_bindings(self.sites_enabled)
            if urlsplit(binding["url"]).hostname == hostname
        ]

    def _ensure_http_site(self, hostname: str, target_ip: str, target_port: int) -> None:
        available_path = self.sites_available / hostname
        enabled_path = self.sites_enabled / hostname

        if available_path.exists():
            if not enabled_path.exists():
                enabled_path.symlink_to(available_path)
                try:
                    self._test_and_reload_nginx()
                except RuntimeError:
                    enabled_path.unlink(missing_ok=True)
                    raise
            return

        self.sites_available.mkdir(parents=True, exist_ok=True)
        self.sites_enabled.mkdir(parents=True, exist_ok=True)
        available_path.write_text(
            self._render_http_site(hostname, target_ip, target_port),
            encoding="utf-8",
        )
        try:
            enabled_path.symlink_to(available_path)
            self._test_and_reload_nginx()
        except (OSError, RuntimeError):
            enabled_path.unlink(missing_ok=True)
            available_path.unlink(missing_ok=True)
            raise

    def _enable_https(self, hostname: str) -> None:
        certbot = shutil.which("certbot")
        if not certbot:
            raise RuntimeError("certbot がインストールされていません。")
        result = subprocess.run(
            [
                certbot,
                "--nginx",
                "-d",
                hostname,
                "--non-interactive",
                "--agree-tos",
                "--redirect",
                "--keep-until-expiring",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if result.returncode != 0:
            message = (result.stderr or result.stdout).strip().splitlines()
            raise RuntimeError(message[-1] if message else "certbot の実行に失敗しました。")

    def _test_and_reload_nginx(self) -> None:
        nginx = shutil.which("nginx")
        systemctl = shutil.which("systemctl")
        if not nginx or not systemctl:
            raise RuntimeError("nginx または systemctl が見つかりません。")

        test_result = subprocess.run(
            [nginx, "-t"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if test_result.returncode != 0:
            message = (test_result.stderr or test_result.stdout).strip().splitlines()
            raise RuntimeError(message[-1] if message else "nginx 設定の検証に失敗しました。")

        reload_result = subprocess.run(
            [systemctl, "reload", "nginx"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if reload_result.returncode != 0:
            message = (reload_result.stderr or reload_result.stdout).strip().splitlines()
            raise RuntimeError(message[-1] if message else "nginx の再読込に失敗しました。")

    def _has_https_binding(self, hostname: str) -> bool:
        return any(
            binding["url"] == f"https://{hostname}/"
            for binding in discover_nginx_bindings(self.sites_enabled)
        )

    @staticmethod
    def _resolve_ipv4(host: str) -> set[str]:
        clean_host = host.strip()
        if not clean_host:
            return set()
        try:
            return {str(ipaddress.ip_address(clean_host))}
        except ValueError:
            pass
        try:
            return {
                address[4][0]
                for address in socket.getaddrinfo(clean_host, None, socket.AF_INET, socket.SOCK_STREAM)
            }
        except socket.gaierror:
            return set()

    @staticmethod
    def _render_http_site(hostname: str, target_ip: str, target_port: int) -> str:
        return f"""server {{
    listen 80;
    listen [::]:80;

    server_name {hostname};

    location / {{
        proxy_pass http://{target_ip}:{target_port};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }}
}}
"""
