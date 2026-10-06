from __future__ import annotations

from pathlib import Path

from .db import get_connection
from .models import PublishRuleInput


class Repository:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def get_settings(self) -> dict[str, str]:
        with get_connection(self.database_path) as connection:
            rows = connection.execute("SELECT key, value FROM settings ORDER BY key").fetchall()
        return {row["key"]: row["value"] for row in rows}

    def upsert_setting(self, key: str, value: str) -> None:
        with get_connection(self.database_path) as connection:
            connection.execute(
                """
                INSERT INTO settings(key, value) VALUES(?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (key, value),
            )

    def add_vpn_client(self, name: str, export_path: str) -> None:
        with get_connection(self.database_path) as connection:
            connection.execute(
                "INSERT INTO vpn_clients(name, export_path) VALUES(?, ?)",
                (name, export_path),
            )

    def list_vpn_clients(self) -> list[dict]:
        with get_connection(self.database_path) as connection:
            rows = connection.execute(
                "SELECT id, name, export_path, created_at FROM vpn_clients ORDER BY created_at DESC, id DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def get_vpn_client(self, client_id: int) -> dict | None:
        with get_connection(self.database_path) as connection:
            row = connection.execute(
                "SELECT id, name, export_path, created_at FROM vpn_clients WHERE id = ?",
                (client_id,),
            ).fetchone()
        return dict(row) if row else None

    def add_publish_rule(self, rule: PublishRuleInput) -> None:
        with get_connection(self.database_path) as connection:
            connection.execute(
                """
                INSERT INTO publish_rules(name, protocol, public_bind_ip, public_port, target_ip, target_port, enabled)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule.name,
                    rule.protocol,
                    rule.public_bind_ip,
                    rule.public_port,
                    rule.target_ip,
                    rule.target_port,
                    int(rule.enabled),
                ),
            )

    def list_publish_rules(self) -> list[dict]:
        with get_connection(self.database_path) as connection:
            rows = connection.execute(
                """
                SELECT id, name, protocol, public_bind_ip, public_port, target_ip, target_port, enabled, created_at
                FROM publish_rules
                ORDER BY created_at DESC, id DESC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def get_publish_rule(self, rule_id: int) -> dict | None:
        with get_connection(self.database_path) as connection:
            row = connection.execute(
                """
                SELECT id, name, protocol, public_bind_ip, public_port, target_ip, target_port, enabled, created_at
                FROM publish_rules
                WHERE id = ?
                """,
                (rule_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_public_ports(self, protocol: str, public_bind_ip: str) -> set[int]:
        with get_connection(self.database_path) as connection:
            rows = connection.execute(
                """
                SELECT public_port
                FROM publish_rules
                WHERE protocol = ?
                  AND (
                    public_bind_ip = ?
                    OR public_bind_ip = '0.0.0.0'
                    OR ? = '0.0.0.0'
                  )
                """,
                (protocol, public_bind_ip, public_bind_ip),
            ).fetchall()
        return {int(row["public_port"]) for row in rows}

    def toggle_publish_rule(self, rule_id: int) -> None:
        with get_connection(self.database_path) as connection:
            connection.execute(
                """
                UPDATE publish_rules
                SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END
                WHERE id = ?
                """,
                (rule_id,),
            )

    def delete_publish_rule(self, rule_id: int) -> None:
        with get_connection(self.database_path) as connection:
            connection.execute("DELETE FROM publish_rules WHERE id = ?", (rule_id,))
