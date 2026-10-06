from __future__ import annotations

import ipaddress
import re
import subprocess
from pathlib import Path

from .config import Paths
from .repository import Repository


class OpenVPNManager:
    def __init__(self, paths: Paths, repository: Repository) -> None:
        self.paths = paths
        self.repository = repository

    def load_defaults(self) -> dict[str, str]:
        settings = self.repository.get_settings()
        if settings:
            return settings

        defaults = {
            "remote_host": self._detect_remote_host(),
            "remote_port": self._parse_server_conf("port", "1194"),
            "protocol": self._parse_server_conf("proto", "udp"),
            "cipher": self._extract_from_sample(r"^cipher\s+(.+)$", "AES-256-GCM"),
            "auth": self._extract_from_sample(r"^auth\s+(.+)$", "SHA256"),
            "vpn_interface": "tun0",
        }
        for key, value in defaults.items():
            self.repository.upsert_setting(key, value)
        return defaults

    def create_client(self, client_name: str) -> Path:
        safe_name = self._validate_name(client_name)
        export_path = self.paths.export_dir / f"{safe_name}.ovpn"
        if export_path.exists():
            raise ValueError(f"client profile already exists: {export_path}")

        self._run_easyrsa(["build-client-full", safe_name, "nopass"])
        profile = self._build_profile(safe_name)
        export_path.parent.mkdir(parents=True, exist_ok=True)
        export_path.write_text(profile, encoding="utf-8")
        self.repository.add_vpn_client(safe_name, str(export_path))
        return export_path

    def _run_easyrsa(self, args: list[str]) -> None:
        easyrsa = self.paths.easy_rsa_dir / "easyrsa"
        if not easyrsa.exists():
            raise RuntimeError(f"Easy-RSA not found: {easyrsa}")
        command = [str(easyrsa), *args]
        result = subprocess.run(
            command,
            cwd=self.paths.easy_rsa_dir,
            env={"EASYRSA_BATCH": "1"},
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Easy-RSA failed")

    def _build_profile(self, client_name: str) -> str:
        settings = self.load_defaults()
        ca = (self.paths.easy_rsa_dir / "pki" / "ca.crt").read_text(encoding="utf-8").strip()
        cert = (self.paths.easy_rsa_dir / "pki" / "issued" / f"{client_name}.crt").read_text(encoding="utf-8")
        key = (self.paths.easy_rsa_dir / "pki" / "private" / f"{client_name}.key").read_text(encoding="utf-8").strip()
        ta = (self.paths.openvpn_server_dir / "ta.key").read_text(encoding="utf-8").strip()
        cert_block = self._extract_certificate(cert)
        remote_host = settings.get("remote_host", "").strip()
        if not remote_host:
            raise ValueError("remote_host is empty. Update settings first.")

        return (
            "client\n"
            "dev tun\n"
            f"proto {settings.get('protocol', 'udp')}\n"
            f"remote {remote_host} {settings.get('remote_port', '1194')}\n"
            "resolv-retry infinite\n"
            "nobind\n"
            "persist-key\n"
            "persist-tun\n"
            "remote-cert-tls server\n"
            "tls-client\n"
            "key-direction 1\n"
            f"cipher {settings.get('cipher', 'AES-256-GCM')}\n"
            f"auth {settings.get('auth', 'SHA256')}\n"
            "verb 3\n\n"
            f"<ca>\n{ca}\n</ca>\n"
            f"<key>\n{key}\n</key>\n"
            f"<cert>\n{cert_block}\n</cert>\n"
            f"<tls-auth>\n{ta}\n</tls-auth>\n"
        )

    def _parse_server_conf(self, key: str, default: str) -> str:
        server_conf = self.paths.openvpn_server_dir / "server.conf"
        if not server_conf.exists():
            return default
        pattern = re.compile(rf"^\s*{re.escape(key)}\s+(.+?)\s*$")
        for line in server_conf.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                continue
            match = pattern.match(stripped)
            if match:
                return match.group(1)
        return default

    def _detect_remote_host(self) -> str:
        ovpn_files = sorted(self.paths.ovpn_dir.glob("*.ovpn"))
        remote_pattern = re.compile(r"^remote\s+(\S+)\s+\d+")
        for path in ovpn_files:
            for line in path.read_text(encoding="utf-8").splitlines():
                match = remote_pattern.match(line.strip())
                if match:
                    return match.group(1)
        return ""

    def _extract_from_sample(self, pattern: str, default: str) -> str:
        ovpn_files = sorted(self.paths.ovpn_dir.glob("*.ovpn"))
        regex = re.compile(pattern, re.MULTILINE)
        for path in ovpn_files:
            match = regex.search(path.read_text(encoding="utf-8"))
            if match:
                return match.group(1).strip()
        return default

    def _extract_certificate(self, content: str) -> str:
        match = re.search(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            content,
            re.DOTALL,
        )
        if not match:
            raise ValueError("could not extract certificate block")
        return match.group(0).strip()

    def _validate_name(self, client_name: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", client_name):
            raise ValueError("client name must be 1-64 chars and use only letters, numbers, dot, dash, underscore")
        return client_name

    @staticmethod
    def validate_target_ip(value: str) -> str:
        return str(ipaddress.ip_address(value))
