from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Paths:
    project_root: Path
    data_dir: Path
    database: Path
    export_dir: Path
    generated_dir: Path
    easy_rsa_dir: Path = Path("/etc/openvpn/easy-rsa")
    openvpn_server_dir: Path = Path("/etc/openvpn/server")
    ovpn_dir: Path = Path("/etc/openvpn/ovpn")
    sysctl_file: Path = Path("/etc/sysctl.d/99-vps-tunnel-tool.conf")
    systemd_service_file: Path = Path("/etc/systemd/system/vps-tunnel-tool-apply.service")
    web_systemd_service_file: Path = Path("/etc/systemd/system/vps-tunnel-tool-web.service")


def build_paths(project_root: Path) -> Paths:
    data_dir = project_root / "app" / "data"
    export_dir = data_dir / "exports"
    generated_dir = data_dir / "generated"
    return Paths(
        project_root=project_root,
        data_dir=data_dir,
        database=data_dir / "app.db",
        export_dir=export_dir,
        generated_dir=generated_dir,
    )
