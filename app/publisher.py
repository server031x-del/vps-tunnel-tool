from __future__ import annotations

import ipaddress
import socket
import subprocess
from pathlib import Path

from .config import Paths
from .repository import Repository


class Publisher:
    TABLE_NAME = "vps_tunnel_tool"
    AUTO_PORT_START = 18080
    AUTO_PORT_END = 19999

    def __init__(self, paths: Paths, repository: Repository) -> None:
        self.paths = paths
        self.repository = repository

    def validate_rule(
        self,
        name: str,
        protocol: str,
        public_bind_ip: str,
        public_port: int | None,
        target_ip: str,
        target_port: int,
    ) -> dict:
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("name is required")

        clean_protocol = protocol.lower().strip()
        if clean_protocol not in {"tcp", "udp"}:
            raise ValueError("protocol must be tcp or udp")

        bind_ip = public_bind_ip.strip() or "0.0.0.0"
        if bind_ip != "0.0.0.0":
            bind_ip = str(ipaddress.ip_address(bind_ip))

        resolved_public_port = (
            self.find_available_public_port(clean_protocol, bind_ip)
            if public_port in {None, 0}
            else self._validate_port(public_port)
        )

        if resolved_public_port in self.repository.list_public_ports(clean_protocol, bind_ip):
            raise ValueError(f"public port {resolved_public_port}/{clean_protocol} is already registered")

        return {
            "name": clean_name,
            "protocol": clean_protocol,
            "public_bind_ip": bind_ip,
            "public_port": resolved_public_port,
            "target_ip": str(ipaddress.ip_address(target_ip)),
            "target_port": self._validate_port(target_port),
        }

    def find_available_public_port(self, protocol: str, public_bind_ip: str) -> int:
        used_ports = self.repository.list_public_ports(protocol, public_bind_ip)
        for port in range(self.AUTO_PORT_START, self.AUTO_PORT_END + 1):
            if port in used_ports:
                continue
            if self._can_bind(protocol, public_bind_ip, port):
                return port
        raise ValueError("no available public port found in auto-assign range")

    def apply(self) -> Path:
        rules = [rule for rule in self.repository.list_publish_rules() if rule["enabled"]]
        ruleset = self._render_ruleset(rules)
        output_path = self.paths.generated_dir / "vps-tunnel-tool.nft"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(ruleset, encoding="utf-8")

        sysctl_text = "net.ipv4.ip_forward=1\n"
        self.paths.sysctl_file.write_text(sysctl_text, encoding="utf-8")
        subprocess.run(["sysctl", "--system"], check=True, capture_output=True, text=True)
        subprocess.run(["nft", "delete", "table", "ip", self.TABLE_NAME], check=False, capture_output=True, text=True)
        subprocess.run(["nft", "-f", str(output_path)], check=True, capture_output=True, text=True)
        return output_path

    def install_systemd_unit(self, python_bin: str, project_root: Path) -> Path:
        service_text = f"""[Unit]
Description=Apply VPS Tunnel Tool nftables rules
After=network-online.target openvpn-server@server.service
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory={project_root}
ExecStart={python_bin} {project_root / "main.py"} apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
        self.paths.systemd_service_file.write_text(service_text, encoding="utf-8")
        subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True, text=True)
        subprocess.run(["systemctl", "enable", "--now", self.paths.systemd_service_file.name], check=True, capture_output=True, text=True)
        return self.paths.systemd_service_file

    def install_web_systemd_unit(self, python_bin: str, project_root: Path, host: str, port: int) -> Path:
        service_text = f"""[Unit]
Description=VPS Tunnel Tool Web UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={project_root}
EnvironmentFile=/etc/vps-tunnel-tool.env
ExecStart={python_bin} {project_root / "main.py"} runserver --host {host} --port {port}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
        self.paths.web_systemd_service_file.write_text(service_text, encoding="utf-8")
        subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True, text=True)
        subprocess.run(["systemctl", "enable", "--now", self.paths.web_systemd_service_file.name], check=True, capture_output=True, text=True)
        return self.paths.web_systemd_service_file

    def _render_ruleset(self, rules: list[dict]) -> str:
        prerouting_rules: list[str] = []
        postrouting_rules: list[str] = []
        forward_rules: list[str] = []

        for rule in rules:
            prefix = f"ip daddr {rule['public_bind_ip']} " if rule["public_bind_ip"] != "0.0.0.0" else ""
            prerouting_rules.append(
                f"    {prefix}{rule['protocol']} dport {rule['public_port']} dnat to {rule['target_ip']}:{rule['target_port']}"
            )
            postrouting_rules.append(
                f"    ip daddr {rule['target_ip']} {rule['protocol']} dport {rule['target_port']} masquerade"
            )
            forward_rules.append(
                f"    ip daddr {rule['target_ip']} {rule['protocol']} dport {rule['target_port']} accept"
            )
            forward_rules.append(
                f"    ip saddr {rule['target_ip']} {rule['protocol']} sport {rule['target_port']} accept"
            )

        lines = [
            f"table ip {self.TABLE_NAME} {{",
            "  chain prerouting {",
            "    type nat hook prerouting priority dstnat; policy accept;",
            *prerouting_rules,
            "  }",
            "  chain postrouting {",
            "    type nat hook postrouting priority srcnat; policy accept;",
            *postrouting_rules,
            "  }",
            "  chain forward {",
            "    type filter hook forward priority filter; policy accept;",
            *forward_rules,
            "  }",
            "}",
        ]
        return "\n".join(lines) + "\n"

    def _validate_port(self, port: int) -> int:
        value = int(port)
        if value < 1 or value > 65535:
            raise ValueError("port must be between 1 and 65535")
        return value

    def _can_bind(self, protocol: str, public_bind_ip: str, port: int) -> bool:
        bind_ip = "" if public_bind_ip == "0.0.0.0" else public_bind_ip
        sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
        sock = socket.socket(socket.AF_INET, sock_type)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_ip, port))
            return True
        except OSError:
            return False
        finally:
            sock.close()
