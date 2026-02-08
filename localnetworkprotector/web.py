import logging
from flask import Flask, render_template, request, redirect, url_for, flash
from datetime import datetime
import json
import sqlite3

log = logging.getLogger(__name__)

def create_app(config, db_manager, monitor_service):
    app = Flask(__name__)
    app.secret_key = 'dev-secret-key-change-in-prod'  # Simple key for flash messages

    @app.template_filter('json_load')
    def json_load_filter(s):
        if not s: return {}
        try:
            return json.loads(s)
        except:
            return {}

    @app.route('/')
    def index():
        # Quick stats
        device_count = 0
        scan_count = 0
        recent_alerts = []
        
        try:
            devices = db_manager.get_known_eero_macs()
            device_count = len(devices)
            
            # Get scan count
            conn = sqlite3.connect(db_manager.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM scans")
            scan_count = cursor.fetchone()[0]
            
            # Get Tsunami count
            # Reuse the LIKE logic for now, or trust database manager method if we want to add a count method there.
            # For simplicity, let's just count matching findings here.
            cursor.execute("SELECT COUNT(*) FROM findings WHERE details_json LIKE '%\"service\": \"tsunami-scanner\"%'")
            tsunami_count = cursor.fetchone()[0]

            # Get recent 5 findings
            cursor.execute("SELECT * FROM findings ORDER BY id DESC LIMIT 5")
            cols = [desc[0] for desc in cursor.description]
            recent_alerts = [dict(zip(cols, row)) for row in cursor.fetchall()]
            conn.close()
            
        except Exception as e:
            log.error("Error fetching dashboard stats: %s", e)
            tsunami_count = 0
            
        return render_template('index.html', 
                             device_count=device_count, 
                             scan_count=scan_count,
                             tsunami_count=tsunami_count,
                             recent_alerts=recent_alerts)

    @app.route('/devices')
    def devices():
        eero_devices = []
        try:
            conn = sqlite3.connect(db_manager.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM eero_devices ORDER BY last_seen DESC")
            cols = [desc[0] for desc in cursor.description]
            eero_devices = [dict(zip(cols, row)) for row in cursor.fetchall()]
            conn.close()
        except Exception as e:
            log.error("Error fetching devices: %s", e)
            
        return render_template('devices.html', devices=eero_devices)

    @app.route('/scans')
    def scans():
        scan_history = []
        try:
            conn = sqlite3.connect(db_manager.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 50")
            cols = [desc[0] for desc in cursor.description]
            scan_history = [dict(zip(cols, row)) for row in cursor.fetchall()]
            conn.close()
        except Exception as e:
            log.error("Error fetching scans: %s", e)
            
        return render_template('scans.html', scans=scan_history)

    @app.route('/tsunami')
    def tsunami():
        findings = db_manager.get_tsunami_findings()
        return render_template('tsunami.html', findings=findings)

    @app.route('/scan/trigger', methods=['POST'])
    def trigger_scan():
        ip = request.form.get('ip')
        if ip and monitor_service:
            log.info("Manual scan triggered via Web UI for %s", ip)
            # Run in background to avoid blocking request? 
            # Ideally yes, but _trigger_scan is relatively fast or we trust it.
            # Actually _trigger_scan spawns a thread usually? 
            # Looking at monitor.py, _trigger_scan calls active_scanner.scan_host which is blocking.
            # We should wrap it.
            import threading
            threading.Thread(target=monitor_service._trigger_scan, args=(ip,)).start()
            flash(f"Scan initiated for {ip}", "success")
        else:
            flash("Invalid IP or Monitor Service unavailable", "danger")
        
        return redirect(url_for('devices'))

    return app
