from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PublishRuleInput:
    name: str
    protocol: str
    public_bind_ip: str
    public_port: int
    target_ip: str
    target_port: int
    enabled: bool = True
