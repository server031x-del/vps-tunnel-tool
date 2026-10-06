from __future__ import annotations

import argparse
from pathlib import Path

from app.services import ServiceContainer
from app.web import create_app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="VPS Tunnel Tool")
    subparsers = parser.add_subparsers(dest="command")

    runserver = subparsers.add_parser("runserver", help="Run the web UI")
    runserver.add_argument("--host", default="127.0.0.1")
    runserver.add_argument("--port", default=5000, type=int)
    runserver.add_argument("--debug", action="store_true")

    subparsers.add_parser("apply", help="Apply nftables publish rules")

    install = subparsers.add_parser("install-systemd", help="Install systemd auto-apply unit")
    install.add_argument("--python-bin", default="python3")

    web_install = subparsers.add_parser("install-web-systemd", help="Install systemd service for the web UI")
    web_install.add_argument("--python-bin", default="python3")
    web_install.add_argument("--host", default="127.0.0.1")
    web_install.add_argument("--port", default=5000, type=int)

    subparsers.add_parser("init", help="Initialize data directories and default settings")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    project_root = Path(__file__).resolve().parent
    services = ServiceContainer(project_root)
    services.ensure_layout()
    services.openvpn.load_defaults()

    if args.command in {None, "runserver"}:
        app = create_app()
        host = getattr(args, "host", "127.0.0.1")
        port = getattr(args, "port", 5000)
        debug = getattr(args, "debug", False)
        app.run(host=host, port=port, debug=debug)
        return

    if args.command == "apply":
        output_path = services.publisher.apply()
        print(f"Applied nftables rules from {output_path}")
        return

    if args.command == "install-systemd":
        service_path = services.publisher.install_systemd_unit(args.python_bin, project_root)
        print(f"Installed {service_path}")
        return

    if args.command == "install-web-systemd":
        service_path = services.publisher.install_web_systemd_unit(args.python_bin, project_root, args.host, args.port)
        print(f"Installed {service_path}")
        return

    if args.command == "init":
        print(f"Initialized {services.paths.database}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
