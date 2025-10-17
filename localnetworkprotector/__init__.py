"""
LocalNetworkProtector package.

This package provides utilities for monitoring local network traffic on a
Raspberry Pi and detecting potentially malicious activity. The package is
designed to be used by the `lnp-main.py` entrypoint script but can also be
imported for custom integrations.
"""

__all__ = [
    "config",
    "detector",
    "monitor",
    "notifier",
    "alerts",
    "packet_utils",
    "version",
]

version = "0.1.0"
