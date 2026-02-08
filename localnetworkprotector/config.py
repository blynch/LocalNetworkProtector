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
    match_patterns: List[str] = field(
        default_factory=lambda: [
            "malware",
            "botnet",
            "password",
            "exploit",
            "cmd.exe",
        ]
    )
    excluded_ports: List[int] = field(default_factory=list)
    severity: str = "medium"


@dataclass
class DnsExfilRuleConfig:
    enabled: bool = True
    max_label_length: int = 40
    severity: str = "medium"
    allow_patterns: List[str] = field(
        default_factory=lambda: ["*.local", "*.arpa"]
    )


@dataclass
class ActiveScanningConfig:
    enabled: bool = False
    ports: str = "top-100"  # nmap syntax, e.g. "80,443" or "1-1000"
    arguments: str = "-sV -T4"  # nmap arguments
    rescan_interval_minutes: int = 60  # How often to re-scan a host = 3600


@dataclass
class VulnerabilityScanningConfig:
    enabled: bool = False
    nvd_api_key: str = ""
    osv_enabled: bool = True
    min_severity: str = "medium"


@dataclass
class TsunamiConfig:
    enabled: bool = False
    docker_image: str = "localnetworkprotector/tsunami"
    scan_timeout: int = 600


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
    trusted_ips: List[str] = field(default_factory=list)
    tsunami: TsunamiConfig = field(default_factory=TsunamiConfig)


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
class ScheduledScanConfig:
    enabled: bool = False
    schedule_time: str = "03:00"  # 24-hour format HH:MM
    target_subnets: List[str] = field(default_factory=list)



@dataclass
class EeroConfig:
    enabled: bool = False
    session_path: str = "eero.session"
    check_interval_seconds: int = 300


@dataclass
class WebConfig:
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 5000
    ssl_enabled: bool = False
    ssl_port: int = 5443
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None


@dataclass
class Config:
    log_level: str = "INFO"
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    active_scanning: ActiveScanningConfig = field(default_factory=ActiveScanningConfig)
    vulnerability_scanning: VulnerabilityScanningConfig = field(default_factory=VulnerabilityScanningConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    notification: NotificationConfig = field(default_factory=NotificationConfig)
    eero: EeroConfig = field(default_factory=EeroConfig)
    web: WebConfig = field(default_factory=WebConfig)
    scheduled_scan: ScheduledScanConfig = field(default_factory=ScheduledScanConfig)
    database_path: str = "lnp_database.db"
    
    @classmethod
    def load(cls, path: str) -> "Config":
        # ... (rest of load method logic is handled by global functions below)
        pass


# ... (skipping unchanged code) ...

def build_config(data: Dict[str, Any]) -> Config:
    """Build Config dataclass from raw dict."""
    # ...
    eero = _dataclass_from_dict(
        EeroConfig, data.get("eero", {})
    )
    scheduled_scan = _dataclass_from_dict(
        ScheduledScanConfig, data.get("scheduled_scan", {})
    )
    log_level = data.get("log_level", "INFO")

    return Config(
        capture=capture,
        detection=detection,
        active_scanning=active_scanning,
        vulnerability_scanning=vulnerability_scanning,
        notification=notifications,
        eero=eero,
        scheduled_scan=scheduled_scan,
        log_level=log_level,
    )


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


def load_config(path: Optional[str] = None) -> Config:
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


def build_config(data: Dict[str, Any]) -> Config:
    """Build Config dataclass from raw dict."""
    capture = _dataclass_from_dict(CaptureConfig, data.get("capture", {}))
    detection_data = data.get("detection", {})
    detection = DetectionConfig(
        port_scan=_dataclass_from_dict(
            PortScanRuleConfig, detection_data.get("port_scan", {})
        ),
        suspicious_ports=_dataclass_from_dict(
            SuspiciousPortRuleConfig,
            detection_data.get("suspicious_ports", {}),
        ),
        suspicious_payload=_dataclass_from_dict(
            SuspiciousPayloadRuleConfig,
            detection_data.get("suspicious_payload", {}),
        ),
        dns_exfiltration=_dataclass_from_dict(
            DnsExfilRuleConfig,
            detection_data.get("dns_exfiltration", {}),
        ),
        trusted_ips=detection_data.get("trusted_ips", []),
    )
    active_scanning = _dataclass_from_dict(
        ActiveScanningConfig, data.get("active_scanning", {})
    )
    vulnerability_scanning = _dataclass_from_dict(
        VulnerabilityScanningConfig, data.get("vulnerability_scanning", {})
    )
    notifications = _dataclass_from_dict(
        NotificationConfig, data.get("notification", {})
    )
    eero = _dataclass_from_dict(
        EeroConfig, data.get("eero", {})
    )
    scheduled_scan = _dataclass_from_dict(
        ScheduledScanConfig, data.get("scheduled_scan", {})
    )
    log_level = data.get("log_level", "INFO")

    return Config(
        capture=capture,
        detection=detection,
        active_scanning=active_scanning,
        vulnerability_scanning=vulnerability_scanning,
        notification=notifications,
        eero=eero,
        scheduled_scan=scheduled_scan,
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
