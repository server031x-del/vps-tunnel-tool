from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit


DEFAULT_NGINX_SITES_DIR = Path("/etc/nginx/sites-enabled")


def discover_nginx_bindings(sites_dir: Path = DEFAULT_NGINX_SITES_DIR) -> list[dict]:
    """Read enabled nginx sites and return static server-name/upstream bindings."""
    bindings: list[dict] = []
    if not sites_dir.is_dir():
        return bindings

    for config_path in sorted(sites_dir.iterdir()):
        if not config_path.is_file():
            continue
        try:
            config = config_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue

        for block in _extract_server_blocks(_strip_comments(config)):
            names = _server_names(block)
            if not names:
                continue
            public_scheme = "https" if _uses_tls(block) else "http"
            for proxy_url in re.findall(r"\bproxy_pass\s+([^;\s]+)\s*;", block):
                upstream = _parse_static_upstream(proxy_url)
                if not upstream:
                    continue
                for name in names:
                    bindings.append(
                        {
                            "url": f"{public_scheme}://{name}/",
                            "target_host": upstream[0],
                            "target_port": upstream[1],
                            "source": str(config_path),
                        }
                    )

    return _deduplicate_bindings(bindings)


def discover_nginx_server_names(sites_dir: Path = DEFAULT_NGINX_SITES_DIR) -> list[str]:
    names: set[str] = set()
    if not sites_dir.is_dir():
        return []

    for config_path in sorted(sites_dir.iterdir()):
        if not config_path.is_file():
            continue
        try:
            config = config_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for block in _extract_server_blocks(_strip_comments(config)):
            names.update(_server_names(block))

    return sorted(names)


def infer_base_domains(server_names: list[str], preferred_domains: list[str] | None = None) -> list[str]:
    valid_names = {
        name.strip().lower().strip(".")
        for name in server_names
        if _is_domain_name(name.strip().lower().strip("."))
    }
    roots = {
        name
        for name in valid_names
        if not any(name.endswith(f".{parent}") for parent in valid_names if parent != name)
    }

    ordered: list[str] = []
    for domain in preferred_domains or []:
        clean_domain = domain.strip().lower().strip(".")
        if _is_domain_name(clean_domain) and clean_domain not in ordered:
            ordered.append(clean_domain)
    for domain in sorted(roots):
        if domain not in ordered:
            ordered.append(domain)
    return ordered


def attach_assigned_urls(
    rules: list[dict],
    bindings: list[dict],
    public_host: str = "",
) -> list[dict]:
    """Attach nginx URLs by matching either the VPN target or public TCP port."""
    local_proxy_hosts = {"127.0.0.1", "0.0.0.0", "localhost", "::1"}
    if public_host:
        local_proxy_hosts.add(public_host.strip().lower())

    for rule in rules:
        assigned_urls: set[str] = set()
        if rule["protocol"] == "tcp":
            for binding in bindings:
                target_matches = (
                    binding["target_host"] == rule["target_ip"].lower()
                    and binding["target_port"] == int(rule["target_port"])
                )
                public_port_matches = (
                    binding["target_host"] in local_proxy_hosts
                    and binding["target_port"] == int(rule["public_port"])
                )
                if target_matches or public_port_matches:
                    assigned_urls.add(binding["url"])

        rule["assigned_urls"] = sorted(
            assigned_urls,
            key=lambda url: (not url.startswith("https://"), url),
        )

    return rules


def _strip_comments(config: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in config.splitlines())


def _extract_server_blocks(config: str) -> list[str]:
    blocks: list[str] = []
    for match in re.finditer(r"\bserver\s*\{", config):
        depth = 1
        index = match.end()
        while index < len(config) and depth:
            if config[index] == "{":
                depth += 1
            elif config[index] == "}":
                depth -= 1
            index += 1
        if depth == 0:
            blocks.append(config[match.end() : index - 1])
    return blocks


def _server_names(block: str) -> list[str]:
    names: list[str] = []
    for directive in re.findall(r"\bserver_name\s+([^;]+);", block):
        for name in directive.split():
            clean_name = name.strip().lower()
            if clean_name and clean_name != "_" and "$" not in clean_name and "*" not in clean_name:
                names.append(clean_name)
    return list(dict.fromkeys(names))


def _uses_tls(block: str) -> bool:
    return bool(re.search(r"\blisten\s+[^;]*\bssl\b[^;]*;", block) or "ssl_certificate" in block)


def _parse_static_upstream(proxy_url: str) -> tuple[str, int] | None:
    if "$" in proxy_url:
        return None
    parsed = urlsplit(proxy_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None
    return parsed.hostname.lower(), port


def _deduplicate_bindings(bindings: list[dict]) -> list[dict]:
    unique: dict[tuple[str, str, int], dict] = {}
    for binding in bindings:
        key = (binding["url"], binding["target_host"], binding["target_port"])
        unique[key] = binding
    return list(unique.values())


def _is_domain_name(value: str) -> bool:
    if len(value) > 253 or "." not in value:
        return False
    return all(
        bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label))
        for label in value.split(".")
    )
