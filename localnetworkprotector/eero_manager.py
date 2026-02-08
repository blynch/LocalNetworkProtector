
import logging
import os
import time
from typing import Dict, List, Optional, Set

try:
    import eero
except ImportError:
    eero = None

from localnetworkprotector.config import EeroConfig

log = logging.getLogger(__name__)

class CustomSessionStorage:
    def __init__(self, filename):
        self.filename = filename
        self._cookie = None
        self.load()

    @property
    def cookie(self):
        return self._cookie

    @cookie.setter
    def cookie(self, value):
        self._cookie = value
        self.save()

    def save(self):
        try:
             with open(self.filename, 'w') as f:
                f.write(self._cookie if self._cookie else '')
        except Exception as e:
            log.error("Failed to save eero session: %s", e)

    def load(self):
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r') as f:
                    self._cookie = f.read().strip()
            except Exception as e:
                log.error("Failed to load eero session: %s", e)

class EeroManager:
    """Manages Eero session and device polling."""

    def __init__(self, config: EeroConfig, database=None):
        self.config = config
        self.database = database
        self._eero = None
        self._account = None
        self._networks = []
        self._known_devices: Set[str] = set()
        self._initialized = False

        if not self.config.enabled:
            return

        if eero is None:
            log.warning("Eero library not installed. Eero integration disabled.")
            return

        self._initialize_api()

    def _initialize_api(self):
        """Load session and initialize Eero client."""
        # Note: v0.0.2 SessionStorage hardcodes the file path (e.g. 'eero.session')
        # We try to ensure we are in the right directory or that the file exists.
        # implementation detail: SessionStorage v0.0.2 usually manages 'eero.session' in CWD.
        
        try:
            # Connect to the session file using our CustomSessionStorage
            # eero.SessionStorage in v0.0.2 is broken/read-only.
            session = CustomSessionStorage(self.config.session_path)
            self._eero = eero.Eero(session)
            
            if self._eero.needs_login():
                log.error("Eero session expired or invalid. Please run eero_login.py.")
                self._eero = None
                return

            self._account = self._eero.account()
            self._networks = self._account.get('networks', {}).get('data', [])
            log.info("EeroManager initialized. Found %d networks: %s", len(self._networks), [n.get('name') for n in self._networks])
            self._initialized = True
            
            # Populate initial known devices from DB if available
            # Populate initial known devices from DB if available
            if self.database:
                 db_devices = self.database.get_known_eero_macs()
                 self._known_devices.update(db_devices)
                 log.info("Loaded %d known devices from database.", len(db_devices))

        except Exception as e:
            log.error("Failed to initialize Eero manager: %s", e)
            self._eero = None

    def get_devices(self) -> List[Dict]:
        """Fetch list of connected devices from all networks."""
        if not self._initialized or not self._eero:
            return []

        all_devices = []
        for net in self._networks:
            try:
                # API detail: eero.devices(network_id)
                url = net.get('url') # e.g. /2.2/networks/123...
                # The library exposes .devices(network_id) method?
                # looking at lib usage manually:
                # eero.devices(network_id) 
                # but 'network' object in response usually has 'url' property
                # library takes network_id.
                # network id is typically at end of url or 'id' field
                
                # Let's try to parse ID or use convenience method if available
                # Usually: devices = eero.devices(net['url'])
                devices_response = self._eero.devices(url)
                devices = devices_response if isinstance(devices_response, list) else devices_response.get('data', [])
                all_devices.extend(devices)
            except Exception as e:
                log.error("Failed to fetch devices for network %s: %s", net.get('name'), e)

        return all_devices

    def check_for_new_devices(self) -> List[Dict]:
        """Poll for devices and return newly discovered ones."""
        current_devices = self.get_devices()
        new_devices = []
        
        current_macs = set()

        for dev in current_devices:
            mac = dev.get('mac')
            if not mac:
                continue
            
            current_macs.add(mac)

            if mac not in self._known_devices:
                # New device!
                is_connected = dev.get('connected', False)
                if is_connected: # Only alert if currently connected? Or added at all?
                    # Let's alert if we see it for the first time
                    self._known_devices.add(mac)
                    new_devices.append(dev)
                    
                    if self.database:
                        self.database.record_eero_device(dev)
        
        return new_devices

    def get_total_device_count(self) -> int:
        return len(self.get_devices())
