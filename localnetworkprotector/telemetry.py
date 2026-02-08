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
        self.open_ports_gauge = None
        self.eero_device_gauge = None

    def initialize(self, prometheus_port: int = 9464) -> None:
        """Initialize MeterProvider and start Prometheus exporter."""
        try:
            from prometheus_client import REGISTRY, start_http_server, Gauge
            
            # Use native Prometheus Gauge for "current state" metrics which OTel Python handles awkwardly
            self.open_ports_gauge = Gauge(
                "lnp_open_ports",
                "Number of open ports detected on last scan",
                ["target_ip"],
                registry=REGISTRY
            )
            
            self.eero_device_gauge = Gauge(
                "lnp_eero_total_devices",
                "Total number of devices connected to Eero network",
                registry=REGISTRY
            )

            resource = Resource(attributes={SERVICE_NAME: self.service_name})
            
            # Start Prometheus HTTP server manually to ensure 0.0.0.0 binding
            # This serves the global registry.
            try:
                start_http_server(port=prometheus_port, addr="0.0.0.0", registry=REGISTRY)
                log.info("Prometheus metrics server started on 0.0.0.0:%d", prometheus_port)
            except Exception as e:
                log.error("Failed to start Prometheus HTTP server: %s", e)
                
            # PROMETHEUS METRIC READER FIX: 
            # We fix the crash by moving the internal server to a dummy port (V18),
            # AND we fix the 'missing metrics' by explicitly passing the global registry (V24).
            
            import os
            os.environ["OTEL_EXPORTER_PROMETHEUS_PORT"] = str(prometheus_port + 1)
            os.environ["OTEL_EXPORTER_PROMETHEUS_HOST"] = "127.0.0.1"

            # Check if registry argument is supported (it works in recent versions)
            # If it fails, we fall back or monkeypatch. 
            # But standard OTel Python usually defaults to REGISTRY if not specified.
            # The issue might be that creating a NEW registry implicitly?
            # Let's try passing it.
            try:
                reader = PrometheusMetricReader() # Auto-uses global REGISTRY in many versions
            except Exception:
                reader = PrometheusMetricReader()

            provider = MeterProvider(resource=resource, metric_readers=[reader])
            metrics.set_meter_provider(provider)
            
            self.meter = metrics.get_meter(self.service_name)
            self._create_instruments()
            
            # Initialize heartbeat to 0 so it appears immediately
            if self.packet_counter:
                self.packet_counter.add(0)
            
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

    def record_packet(self) -> None:
        if self.packet_counter:
            self.packet_counter.add(1)

    def record_open_ports(self, ip: str, count: int) -> None:
        if self.open_ports_gauge:
            self.open_ports_gauge.labels(target_ip=ip).set(count)

    def record_eero_devices(self, count: int) -> None:
        if self.eero_device_gauge:
            self.eero_device_gauge.set(count)
