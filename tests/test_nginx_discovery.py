from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.nginx_discovery import (
    attach_assigned_urls,
    discover_nginx_bindings,
    infer_base_domains,
)
from app.nginx_url_manager import NginxUrlManager


class NginxDiscoveryTests(unittest.TestCase):
    def test_discovers_https_names_and_matches_vpn_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sites_dir = Path(temp_dir)
            (sites_dir / "files.example.test").write_text(
                """
                server {
                    server_name files.example.test www.files.example.test;
                    location / { proxy_pass http://10.8.0.2:8095; }
                    listen 443 ssl;
                    ssl_certificate /tmp/example.pem;
                }
                """,
                encoding="utf-8",
            )
            bindings = discover_nginx_bindings(sites_dir)
            rules = [
                {
                    "protocol": "tcp",
                    "public_port": 18093,
                    "target_ip": "10.8.0.2",
                    "target_port": 8095,
                }
            ]

            attach_assigned_urls(rules, bindings)

            self.assertEqual(
                rules[0]["assigned_urls"],
                ["https://files.example.test/", "https://www.files.example.test/"],
            )

    def test_matches_nginx_proxy_to_public_port(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sites_dir = Path(temp_dir)
            (sites_dir / "app.example.test").write_text(
                """
                server {
                    listen 80;
                    server_name app.example.test;
                    location / { proxy_pass http://127.0.0.1:18080; }
                }
                """,
                encoding="utf-8",
            )
            bindings = discover_nginx_bindings(sites_dir)
            rules = [
                {
                    "protocol": "tcp",
                    "public_port": 18080,
                    "target_ip": "10.8.0.3",
                    "target_port": 3000,
                }
            ]

            attach_assigned_urls(rules, bindings)

            self.assertEqual(rules[0]["assigned_urls"], ["http://app.example.test/"])

    def test_does_not_assign_http_url_to_udp_rule(self) -> None:
        bindings = [
            {
                "url": "https://app.example.test/",
                "target_host": "10.8.0.3",
                "target_port": 3000,
                "source": "/tmp/example",
            }
        ]
        rules = [
            {
                "protocol": "udp",
                "public_port": 18080,
                "target_ip": "10.8.0.3",
                "target_port": 3000,
            }
        ]

        attach_assigned_urls(rules, bindings)

        self.assertEqual(rules[0]["assigned_urls"], [])

    def test_infers_apex_domains_from_existing_server_names(self) -> None:
        domains = infer_base_domains(
            [
                "example.test",
                "admin.example.test",
                "fileserver.example.test",
                "second.example",
                "www.second.example",
            ],
            ["example.test"],
        )

        self.assertEqual(domains, ["example.test", "second.example"])


class NginxUrlManagerTests(unittest.TestCase):
    def test_assign_creates_http_site_and_reports_required_dns(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manager = NginxUrlManager(root / "available", root / "enabled")
            rule = {
                "protocol": "tcp",
                "target_ip": "10.8.0.3",
                "target_port": 8080,
            }

            with patch.object(manager, "_test_and_reload_nginx"), patch.object(
                manager,
                "_resolve_ipv4",
                side_effect=lambda host: {"203.0.113.10"} if host == "203.0.113.10" else set(),
            ):
                result = manager.assign(
                    rule,
                    "sample-app",
                    "example.test",
                    "203.0.113.10",
                    enable_https=True,
                )

            config = (root / "available" / "sample-app.example.test").read_text(encoding="utf-8")
            self.assertIn("server_name sample-app.example.test;", config)
            self.assertIn("proxy_pass http://10.8.0.3:8080;", config)
            self.assertEqual(result["url"], "http://sample-app.example.test/")
            self.assertFalse(result["dns_ready"])
            self.assertIn("A レコード", result["warning"])

    def test_rejects_unsafe_subdomain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manager = NginxUrlManager(root / "available", root / "enabled")
            rule = {
                "protocol": "tcp",
                "target_ip": "10.8.0.3",
                "target_port": 8080,
            }

            with self.assertRaises(ValueError):
                manager.assign(
                    rule,
                    "../../bad",
                    "example.test",
                    "203.0.113.10",
                    enable_https=False,
                )

    def test_https_retry_requires_dns_to_point_to_public_host(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manager = NginxUrlManager(root / "available", root / "enabled")
            rule = {
                "protocol": "tcp",
                "target_ip": "10.8.0.3",
                "target_port": 8080,
            }
            with patch.object(manager, "_test_and_reload_nginx"):
                manager.assign(
                    rule,
                    "sample-app",
                    "example.test",
                    "203.0.113.10",
                    enable_https=False,
                )

            with patch.object(
                manager,
                "_resolve_ipv4",
                side_effect=lambda host: {"203.0.113.10"} if host == "203.0.113.10" else set(),
            ), self.assertRaisesRegex(ValueError, "DNSが未反映"):
                manager.enable_https(rule, "sample-app.example.test", "203.0.113.10")

    def test_https_retry_enables_certificate_when_dns_is_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manager = NginxUrlManager(root / "available", root / "enabled")
            rule = {
                "protocol": "tcp",
                "target_ip": "10.8.0.3",
                "target_port": 8080,
            }
            with patch.object(manager, "_test_and_reload_nginx"):
                manager.assign(
                    rule,
                    "sample-app",
                    "example.test",
                    "203.0.113.10",
                    enable_https=False,
                )

            with patch.object(manager, "_resolve_ipv4", return_value={"203.0.113.10"}), patch.object(
                manager,
                "_has_https_binding",
                side_effect=[False, True],
            ), patch.object(manager, "_enable_https") as enable_https:
                result = manager.enable_https(
                    rule,
                    "sample-app.example.test",
                    "203.0.113.10",
                )

            enable_https.assert_called_once_with("sample-app.example.test")
            self.assertEqual(result["url"], "https://sample-app.example.test/")


if __name__ == "__main__":
    unittest.main()
