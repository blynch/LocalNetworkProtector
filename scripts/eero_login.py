#!/usr/bin/env python3
"""
Interactive script to login to Eero and save session cookie.
Run this once to authenticate.
"""
import argparse
import sys
import os
from pathlib import Path

try:
    import eero
except ImportError:
    print("Error: 'eero' library not found. Please run: pip install eero", file=sys.stderr)
    sys.exit(1)

import os

class CustomSessionStorage:
    def __init__(self, filename='eero.session'):
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
        with open(self.filename, 'w') as f:
            f.write(self._cookie if self._cookie else '')

    def load(self):
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as f:
                self._cookie = f.read().strip()

def main():
    # The eero library (v0.0.2) SessionStorage is broken/read-only.
    # We use our CustomSessionStorage to handle read/write of the session file.
    session_store = CustomSessionStorage()
    print(f"[*] Using custom session storage (saving to 'eero.session').")
    eero_client = eero.Eero(session_store)

    if eero_client.needs_login():
        print("[-] Valid session not found. Starting login flow...")
        user_identifier = input("Enter your Eero email or phone number: ").strip()
        
        try:
            # Step 1: Request login (sends SMS/Email)
            print(f"[*] Requesting login code for {user_identifier}...")
            user_token = eero_client.login(user_identifier)
            
            # Step 2: Verify code
            code = input("Enter the verification code sent to you: ").strip()
            print("[*] Verifying code...")
            eero_client.login_verify(code, user_token)
            
            print(f"[+] Login successful! Session saved to default location.")
            print(f"[+] You can now enable eero in config.yaml with eero.session")
            
        except PermissionError:
            print(f"[!] Login failed: Permission denied writing to '{session_store.filename}'.")
            print(f"[!] Try running with sudo: sudo ./venv/bin/python3 scripts/eero_login.py")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Login failed: {e}")
            sys.exit(1)
    else:
        print(f"[+] Valid session found in {args.output}. No login needed.")
        
    # Test fetch
    try:
        account = eero_client.account()
        print(f"[+] Authenticated as: {account.get('name')} ({account.get('email', 'no email')})")
    except Exception as e:
        print(f"[!] Failed to fetch account info: {e}")

if __name__ == "__main__":
    main()
