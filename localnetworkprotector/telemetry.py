import logging
from typing import Optional
from prometheus_client import start_http_server

from opentelemetry import metrics
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import SERVICE_NAME, Resource

log = logging.getLogger(__name__)

class TelemetryManager:
    """Manages OpenTelemetry setup and metric instruments."""

    def __init__(self, service_name: str = "local_network_protector"):
        self.service_name = service_name
        self.meter = None
        
        # Metrics
        self.scan_counter = None
        self.vuln_counter = None
        self.packet_counter = None
        self.alert_counter = None

    def initialize(self, prometheus_port: int = 9464) -> None:
        """Initialize MeterProvider and start Prometheus exporter."""
        try:
            resource = Resource(attributes={SERVICE_NAME: self.service_name})
            
            # Start Prometheus HTTP server manually to ensure 0.0.0.0 binding
            start_http_server(port=prometheus_port, addr="0.0.0.0")
            
            # Create reader without starting a new server (if library allows)
            # or just let it register to the default registry which start_http_server uses.
            # OTel Python Prometheus exporter typically writes to the default registry by default.
            reader = PrometheusMetricReader()
            
            provider = MeterProvider(resource=resource, metric_readers=[reader])
            metrics.set_meter_provider(provider)
            
            self.meter = metrics.get_meter(self.service_name)
            self._create_instruments()
            
            log.info("Telemetry initialized. Prometheus metrics on port %d", prometheus_port)
        except Exception as e:
            log.error("Failed to initialize telemetry: %s", e)

    def _create_instruments(self) -> None:
        if not self.meter:
            return

        self.scan_counter = self.meter.create_counter(
            "lnp.scan.count",
            description="Number of active scans performed",
        )
        self.vuln_counter = self.meter.create_counter(
            "lnp.vulnerability.count",
            description="Number of vulnerabilities detected",
        )
        self.packet_counter = self.meter.create_counter(
            "lnp.packet.processed",
            description="Number of packets processed",
        )
        self.alert_counter = self.meter.create_counter(
            "lnp.alert.count",
            description="Number of detection alerts triggered",
        )

    def record_scan(self, status: str, target_ip: str) -> None:
        if self.scan_counter:
            self.scan_counter.add(1, {"status": status, "target_ip": target_ip})

    def record_vulnerability(self, severity: str, product: str) -> None:
        if self.vuln_counter:
            self.vuln_counter.add(1, {"severity": severity, "product": product})

    def record_alert(self, rule_name: str, severity: str) -> None:
        if self.alert_counter:
            self.alert_counter.add(1, {"rule": rule_name, "severity": severity})
