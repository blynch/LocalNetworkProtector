"""Configuration loading for LocalNetworkProtector."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


DEFAULT_CONFIG_PATHS = (
    Path("/etc/localnetworkprotector/config.yaml"),
    Path.home() / ".config" / "localnetworkprotector" / "config.yaml",
    Path("config.yaml"),
)


@dataclass
class CaptureConfig:
    interface: Optional[str] = None
    bpf_filter: Optional[str] = None
    snaplen: int = 2048
    promisc: bool = True
    store_packets: bool = False


@dataclass
class PortScanRuleConfig:
    enabled: bool = True
    time_window_seconds: int = 60
    max_unique_ports: int = 30
    severity: str = "high"


@dataclass
class SuspiciousPortRuleConfig:
    enabled: bool = True
    ports: List[int] = field(
        default_factory=lambda: [23, 2323, 3389, 5900, 8888]
    )
    severity: str = "medium"


@dataclass
class SuspiciousPayloadRuleConfig:
    enabled: bool = True
    patterns: List[str] = field(
        default_factory=lambda: [
            "malware",
            "botnet",
            "password",
            "exploit",
            "cmd.exe",
        ]
    )
    severity: str = "medium"


@dataclass
class DnsExfilRuleConfig:
    enabled: bool = True
    max_label_length: int = 40
    severity: str = "medium"
    allow_patterns: List[str] = field(default_factory=list)


@dataclass
class DetectionConfig:
    port_scan: PortScanRuleConfig = field(default_factory=PortScanRuleConfig)
    suspicious_ports: SuspiciousPortRuleConfig = field(
        default_factory=SuspiciousPortRuleConfig
    )
    suspicious_payload: SuspiciousPayloadRuleConfig = field(
        default_factory=SuspiciousPayloadRuleConfig
    )
    dns_exfiltration: DnsExfilRuleConfig = field(default_factory=DnsExfilRuleConfig)


@dataclass
class NotificationConfig:
    enabled: bool = True
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    use_tls: bool = True
    username: Optional[str] = None
    password: Optional[str] = None
    sender: Optional[str] = None
    recipients: List[str] = field(default_factory=list)
    min_severity: str = "medium"
    cool_down_seconds: int = 300


@dataclass
class AppConfig:
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    notification: NotificationConfig = field(default_factory=NotificationConfig)
    log_level: str = "INFO"


def _merge_dict(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge override into base dict."""
    for key, value in override.items():
        if (
            key in base
            and isinstance(base[key], dict)
            and isinstance(value, dict)
        ):
            base[key] = _merge_dict(base[key], value)
        else:
            base[key] = value
    return base


def _dataclass_from_dict(datacls, data: Dict[str, Any]):
    field_names = {f.name for f in datacls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    kwargs = {}
    for key, value in data.items():
        if key in field_names:
            kwargs[key] = value
    return datacls(**kwargs)


def load_config(path: Optional[str] = None) -> AppConfig:
    """Load configuration from YAML file and environment overrides."""
    config_dict: Dict[str, Any] = {}

    paths_to_try = [Path(path)] if path else list(DEFAULT_CONFIG_PATHS)
    for candidate in paths_to_try:
        if candidate.is_file():
            with candidate.open("r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            if not isinstance(loaded, dict):
                raise ValueError(f"Config file {candidate} must contain a mapping.")
            config_dict = _merge_dict(config_dict, loaded)

    env_override = _load_env_override()
    if env_override:
        config_dict = _merge_dict(config_dict, env_override)

    return build_config(config_dict)


def build_config(data: Dict[str, Any]) -> AppConfig:
    """Build AppConfig dataclass from raw dict."""
    capture = _dataclass_from_dict(CaptureConfig, data.get("capture", {}))
    detection = DetectionConfig(
        port_scan=_dataclass_from_dict(
            PortScanRuleConfig, data.get("detection", {}).get("port_scan", {})
        ),
        suspicious_ports=_dataclass_from_dict(
            SuspiciousPortRuleConfig,
            data.get("detection", {}).get("suspicious_ports", {}),
        ),
        suspicious_payload=_dataclass_from_dict(
            SuspiciousPayloadRuleConfig,
            data.get("detection", {}).get("suspicious_payload", {}),
        ),
        dns_exfiltration=_dataclass_from_dict(
            DnsExfilRuleConfig,
            data.get("detection", {}).get("dns_exfiltration", {}),
        ),
    )
    notifications = _dataclass_from_dict(
        NotificationConfig, data.get("notification", {})
    )
    log_level = data.get("log_level", "INFO")

    return AppConfig(
        capture=capture,
        detection=detection,
        notification=notifications,
        log_level=log_level,
    )


def _load_env_override() -> Dict[str, Any]:
    """Read overrides from environment variables prefixed with LNP_."""
    overrides: Dict[str, Any] = {}
    for key, value in os.environ.items():
        if not key.startswith("LNP_"):
            continue
        path = key[4:].lower().split("__")
        _assign_override(overrides, path, value)
    return overrides


def _assign_override(target: Dict[str, Any], path: List[str], value: str) -> None:
    cursor = target
    for segment in path[:-1]:
        cursor = cursor.setdefault(segment, {})
    leaf = path[-1]
    cursor[leaf] = _parse_env_value(value)


def _parse_env_value(raw: str) -> Any:
    lowered = raw.lower()
    if lowered in {"true", "yes", "1"}:
        return True
    if lowered in {"false", "no", "0"}:
        return False
    if raw.isdigit():
        return int(raw)
    return raw
