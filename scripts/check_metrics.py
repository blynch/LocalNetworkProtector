#!/usr/bin/env python3
import requests
import sys

def check_metrics(url="http://localhost:9464/metrics"):
    print(f"Checking metrics at {url}...")
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        
        print("SUCCESS: Metrics endpoint is reachable.")
        print("-" * 40)
        
        lines = response.text.splitlines()
        lnp_metrics = [line for line in lines if line.startswith("lnp_")]
        
        if not lnp_metrics:
            print("WARNING: No 'lnp_' metrics found. The app has initialized but recorded no data yet.")
        else:
            print(f"Found {len(lnp_metrics)} LNP metric lines:")
            for m in lnp_metrics:
                if not m.startswith("#"):
                    print(m)
                    
        return 0
    except Exception as e:
        print(f"FAILURE: Could not reach metrics endpoint: {e}")
        print("This suggests the Python application is not running or failed to bind port 9464.")
        return 1

if __name__ == "__main__":
    sys.exit(check_metrics())
