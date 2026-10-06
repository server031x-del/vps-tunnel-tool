from __future__ import annotations

from pathlib import Path

from .config import build_paths
from .db import initialize_database
from .nginx_url_manager import NginxUrlManager
from .openvpn_manager import OpenVPNManager
from .publisher import Publisher
from .repository import Repository


class ServiceContainer:
    def __init__(self, project_root: Path) -> None:
        self.paths = build_paths(project_root)
        initialize_database(self.paths.database)
        self.repository = Repository(self.paths.database)
        self.openvpn = OpenVPNManager(self.paths, self.repository)
        self.publisher = Publisher(self.paths, self.repository)
        self.nginx_urls = NginxUrlManager()

    def ensure_layout(self) -> None:
        self.paths.export_dir.mkdir(parents=True, exist_ok=True)
        self.paths.generated_dir.mkdir(parents=True, exist_ok=True)
