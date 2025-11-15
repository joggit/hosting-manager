#!/usr/bin/env python3
"""
Complete Hosting Manager - All Functionality in One File
Includes: Database, SSL, Domains, First Run, Core Hosting, Process Management, Flask API
"""

import os
import sys
import json
import sqlite3
import subprocess
import re
import shutil
import pwd
import logging
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    "database_path": os.getenv("DB_PATH", "/var/lib/hosting-manager/hosting.db"),
    "web_root": "/var/www/domains",
    "nginx_sites_available": "/etc/nginx/sites-available",
    "nginx_sites_enabled": "/etc/nginx/sites-enabled",
    "ssl_cert_path": "/etc/letsencrypt/live",
    "ssl_email": "admin@smartwave.co.za",
    "first_run_marker": "/var/lib/hosting-manager/.first_run_complete",
    "log_dir": "/var/log/hosting-manager",
    "domains": {
        "smartwave.co.za": {
            "email": "admin@smartwave.co.za",
            "port_range": (3000, 3099),
            "ssl_enabled": True,
        },
        "datablox.co.za": {
            "email": "admin@datablox.co.za",
            "port_range": (3100, 3199),
            "ssl_enabled": True,
        },
        "mondaycafe.co.za": {
            "email": "admin@mondaycafe.co.za",
            "port_range": (3200, 3299),
            "ssl_enabled": True,
        },
    },
}

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# ============================================================================
# CORE SYSTEM DETECTION & SETUP
# ============================================================================


def get_current_user():
    """Get current user safely"""
    try:
        if hasattr(os, "getlogin"):
            try:
                return os.getlogin()
            except OSError:
                pass
        try:
            return pwd.getpwuid(os.getuid()).pw_name
        except KeyError:
            pass
        user = os.getenv("USER") or os.getenv("USERNAME") or os.getenv("LOGNAME")
        if user:
            return user
        return "www-data"
    except Exception:
        return "www-data"


def detect_readonly_filesystem():
    """Detect if filesystem is read-only"""
    readonly_indicators = []
    test_locations = ["/var/lib", "/etc", "/run"]

    for location in test_locations:
        try:
            test_file = f"{location}/hosting-ro-test"
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
            readonly_indicators.append(False)
        except (PermissionError, OSError):
            readonly_indicators.append(True)

    # Check for container indicators
    container_indicators = [
        os.path.exists("/.dockerenv"),
        os.path.exists("/proc/vz"),
        "container" in os.environ.get("SYSTEMD_NSPAWN_API_VFS_WRITABLE", ""),
    ]

    readonly_count = sum(readonly_indicators)
    is_readonly = readonly_count >= len(readonly_indicators) // 2 or any(
        container_indicators
    )

    if is_readonly:
        logger.info("Read-only filesystem detected - using safe mode")
        # Update config for writable locations
        CONFIG.update(
            {
                "database_path": "/tmp/hosting/hosting.db",
                "web_root": "/tmp/www/domains",
                "log_dir": "/tmp/hosting/logs",
                "readonly_mode": True,
            }
        )

        # Create writable directories
        for directory in [
            "/tmp/hosting",
            "/tmp/www/domains",
            "/tmp/hosting/logs",
            "/tmp/nodejs-apps",
            "/tmp/pm2-home",
        ]:
            os.makedirs(directory, mode=0o755, exist_ok=True)

    return is_readonly


# Detect read-only filesystem on startup
IS_READONLY = detect_readonly_filesystem()
IS_ROOT = os.geteuid() == 0


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================


def ensure_database():
    """Ensure database and all tables exist with indexes"""
    try:
        db_path = CONFIG["database_path"]
        db_dir = os.path.dirname(db_path)

        Path(db_dir).mkdir(parents=True, exist_ok=True)
        os.chmod(db_dir, 0o755)

        conn = sqlite3.connect(db_path)

        # Optimize database
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA cache_size=10000")
        conn.execute("PRAGMA foreign_keys=ON")

        cursor = conn.cursor()

        # All tables
        cursor.executescript(
            """
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_name TEXT UNIQUE NOT NULL,
                domain_type TEXT NOT NULL DEFAULT 'subdomain',
                parent_domain TEXT,
                port INTEGER UNIQUE,
                app_name TEXT,
                nginx_config_path TEXT,
                ssl_enabled BOOLEAN DEFAULT FALSE,
                ssl_certificate_id INTEGER,
                status TEXT DEFAULT 'pending',
                site_type TEXT DEFAULT 'node',
                process_manager TEXT DEFAULT 'systemd',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS ssl_certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                certificate_type TEXT NOT NULL DEFAULT 'single',
                certificate_path TEXT,
                private_key_path TEXT,
                fullchain_path TEXT,
                issuer TEXT DEFAULT 'letsencrypt',
                status TEXT DEFAULT 'pending',
                issued_at TIMESTAMP,
                expires_at TIMESTAMP,
                last_renewal_attempt TIMESTAMP,
                renewal_failures INTEGER DEFAULT 0,
                auto_renew BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS certificate_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                certificate_id INTEGER,
                domain_name TEXT NOT NULL,
                is_primary BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (certificate_id) REFERENCES ssl_certificates (id) ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                domain_name TEXT,
                port INTEGER,
                pid INTEGER,
                status TEXT DEFAULT 'stopped',
                process_manager TEXT DEFAULT 'systemd',
                start_command TEXT,
                cwd TEXT,
                memory_usage INTEGER DEFAULT 0,
                cpu_usage REAL DEFAULT 0.0,
                restart_count INTEGER DEFAULT 0,
                type TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS deployment_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_name TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS health_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_name TEXT NOT NULL,
                url TEXT NOT NULL,
                status_code INTEGER,
                response_time REAL,
                status TEXT NOT NULL,
                error_message TEXT,
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_domains_name ON domains(domain_name);
            CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status);
            CREATE INDEX IF NOT EXISTS idx_processes_name ON processes(name);
            CREATE INDEX IF NOT EXISTS idx_processes_status ON processes(status);
            CREATE INDEX IF NOT EXISTS idx_logs_domain ON deployment_logs(domain_name);
            CREATE INDEX IF NOT EXISTS idx_health_domain ON health_checks(domain_name);
        """
        )

        conn.commit()
        conn.close()

        logger.info(f"✅ Database ready: {db_path}")
        return True

    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False


def get_db():
    """Get database connection"""
    return sqlite3.connect(CONFIG["database_path"], timeout=30.0)


# ============================================================================
# FIRST RUN SETUP
# ============================================================================


def is_first_run():
    """Check if this is first run"""
    return not os.path.exists(CONFIG["first_run_marker"])


def mark_setup_complete():
    """Mark first run setup as complete"""
    os.makedirs(os.path.dirname(CONFIG["first_run_marker"]), exist_ok=True)
    with open(CONFIG["first_run_marker"], "w") as f:
        f.write(
            json.dumps(
                {"setup_completed_at": datetime.now().isoformat(), "version": "1.0"}
            )
        )


def run_first_time_setup():
    """Run complete first-time setup"""
    try:
        logger.info("🚀 Running first-time setup...")

        if IS_READONLY:
            logger.info("Read-only mode - skipping package installation")
            mark_setup_complete()
            return True

        if not IS_ROOT:
            logger.warning("Not running as root - limited setup")
            mark_setup_complete()
            return True

        # Install system dependencies
        logger.info("📦 Installing system dependencies...")
        packages = [
            "nginx",
            "sqlite3",
            "certbot",
            "python3-certbot-nginx",
            "curl",
            "git",
            "python3-pip",
            "nodejs",
            "npm",
        ]

        subprocess.run(["apt", "update"], capture_output=True)
        subprocess.run(["apt", "install", "-y"] + packages, capture_output=True)

        # Install Python packages
        for pkg in ["flask", "flask-cors", "gunicorn", "psutil", "requests"]:
            subprocess.run(["pip3", "install", pkg], capture_output=True)

        # Install PM2
        subprocess.run(["npm", "install", "-g", "pm2"], capture_output=True)

        # Create directories
        logger.info("📁 Creating directories...")
        for directory in [
            CONFIG["web_root"],
            CONFIG["nginx_sites_available"],
            CONFIG["nginx_sites_enabled"],
            CONFIG["log_dir"],
        ]:
            os.makedirs(directory, exist_ok=True)

        # Setup nginx
        logger.info("🌐 Setting up nginx...")
        os.makedirs("/etc/nginx/sites-available", exist_ok=True)
        os.makedirs("/etc/nginx/sites-enabled", exist_ok=True)

        # Remove default site
        default_site = "/etc/nginx/sites-enabled/default"
        if os.path.exists(default_site):
            os.remove(default_site)

        subprocess.run(["systemctl", "enable", "nginx"], capture_output=True)
        subprocess.run(["systemctl", "start", "nginx"], capture_output=True)

        # Try to setup SSL certificates
        logger.info("🔐 Setting up SSL certificates...")
        for domain, config in CONFIG["domains"].items():
            try:
                result = subprocess.run(
                    [
                        "certbot",
                        "certonly",
                        "--nginx",
                        "--non-interactive",
                        "--agree-tos",
                        "--email",
                        config["email"],
                        "--cert-name",
                        domain,
                        "-d",
                        domain,
                    ],
                    capture_output=True,
                    timeout=60,
                )

                if result.returncode == 0:
                    logger.info(f"✅ SSL configured for {domain}")
                    store_certificate(domain, "single")
                else:
                    logger.warning(f"⚠️ SSL failed for {domain}")
            except Exception as e:
                logger.warning(f"SSL setup error for {domain}: {e}")

        # Setup auto-renewal
        cron_entry = "0 3 * * * /usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx'\n"
        try:
            result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            current_cron = result.stdout if result.returncode == 0 else ""
            if cron_entry not in current_cron:
                subprocess.run(
                    ["crontab", "-"], input=current_cron + cron_entry, text=True
                )
        except:
            pass

        mark_setup_complete()
        logger.info("🎉 First-time setup completed!")
        return True

    except Exception as e:
        logger.error(f"First-time setup failed: {e}")
        return False


# ============================================================================
# SSL CERTIFICATE MANAGER
# ============================================================================


def store_certificate(domain, cert_type="single"):
    """Store certificate info in database"""
    try:
        cert_path = f"{CONFIG['ssl_cert_path']}/{domain}"
        if not os.path.exists(cert_path):
            return None

        conn = get_db()
        cursor = conn.cursor()

        # Get expiration
        result = subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                f"{cert_path}/fullchain.pem",
                "-noout",
                "-enddate",
            ],
            capture_output=True,
            text=True,
        )

        expires_at = None
        if result.returncode == 0:
            date_str = result.stdout.strip().split("=")[1]
            expires_at = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")

        cursor.execute(
            """
            INSERT OR REPLACE INTO ssl_certificates 
            (domain, certificate_type, certificate_path, private_key_path, 
             fullchain_path, status, issued_at, expires_at)
            VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
        """,
            (
                domain,
                cert_type,
                f"{cert_path}/cert.pem",
                f"{cert_path}/privkey.pem",
                f"{cert_path}/fullchain.pem",
                datetime.now(),
                expires_at,
            ),
        )

        conn.commit()
        cert_id = cursor.lastrowid
        conn.close()
        return cert_id

    except Exception as e:
        logger.error(f"Failed to store certificate: {e}")
        return None


def get_certificate_info(domain):
    """Get certificate information"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM ssl_certificates 
            WHERE domain = ? AND status = 'active'
            ORDER BY created_at DESC LIMIT 1
        """,
            (domain,),
        )

        result = cursor.fetchone()
        conn.close()

        if result:
            return {
                "id": result[0],
                "domain": result[1],
                "certificate_type": result[2],
                "certificate_path": result[3],
                "private_key_path": result[4],
                "fullchain_path": result[5],
                "status": result[7],
                "expires_at": result[9],
            }
        return None
    except Exception as e:
        logger.error(f"Failed to get certificate info: {e}")
        return None


def check_certificate_for_domain(domain):
    """Check if valid certificate exists"""
    cert = get_certificate_info(domain)
    if cert and os.path.exists(cert["fullchain_path"]):
        return {"available": True, "certificate": cert}

    # Check for wildcard
    parts = domain.split(".")
    if len(parts) > 2:
        parent = ".".join(parts[1:])
        wildcard = get_certificate_info(parent)
        if wildcard and wildcard["certificate_type"] == "wildcard":
            return {"available": True, "certificate": wildcard}

    return {"available": False}


def install_certificate(domain, cert_type="single"):
    """Install SSL certificate"""
    try:
        logger.info(f"Installing SSL certificate for {domain}")

        cmd = [
            "certbot",
            "certonly",
            "--nginx",
            "--non-interactive",
            "--agree-tos",
            "--email",
            CONFIG["ssl_email"],
            "--cert-name",
            domain,
            "-d",
            domain,
        ]

        if cert_type == "wildcard":
            cmd.extend(["-d", f"*.{domain}"])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            cert_id = store_certificate(domain, cert_type)
            return {"success": True, "certificate_id": cert_id}
        else:
            return {"success": False, "error": result.stderr}

    except Exception as e:
        return {"success": False, "error": str(e)}


def list_certificates():
    """List all certificates"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM ssl_certificates WHERE status = "active"')
        results = cursor.fetchall()
        conn.close()

        return [
            {
                "id": r[0],
                "domain": r[1],
                "certificate_type": r[2],
                "status": r[7],
                "expires_at": r[9],
            }
            for r in results
        ]
    except Exception as e:
        logger.error(f"Failed to list certificates: {e}")
        return []


# ============================================================================
# DOMAIN MANAGER
# ============================================================================


def validate_subdomain(subdomain):
    """Validate subdomain format"""
    if not subdomain or len(subdomain) > 63:
        return False
    if not (subdomain[0].isalnum() and subdomain[-1].isalnum()):
        return False
    if "--" in subdomain:
        return False
    if not re.match(r"^[a-zA-Z0-9-]+$", subdomain):
        return False
    reserved = ["www", "mail", "ftp", "localhost", "api", "admin", "root", "test"]
    if subdomain.lower() in reserved:
        return False
    return True


def test_nginx_config():
    """Test nginx configuration"""
    try:
        result = subprocess.run(
            ["nginx", "-t"], capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            logger.warning(f"Nginx config test failed: {result.stderr}")
            return False
        return True
    except Exception as e:
        logger.warning(f"Nginx config test error: {e}")
        return False


def create_nginx_config(domain, port, app_name, ssl_enabled=False, ssl_cert=None):
    """Create nginx configuration"""
    try:
        if IS_READONLY:
            logger.info("Read-only mode - skipping nginx config creation")
            return "/tmp/nginx-config"

        config_path = f"{CONFIG['nginx_sites_available']}/{domain}"

        if ssl_enabled and ssl_cert:
            nginx_config = f"""server {{
    listen 80;
    server_name {domain};
    return 301 https://$server_name$request_uri;
}}

server {{
    listen 443 ssl http2;
    server_name {domain};
    
    ssl_certificate {ssl_cert['fullchain_path']};
    ssl_certificate_key {ssl_cert['private_key_path']};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    
    location / {{
        proxy_pass http://localhost:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }}
}}"""
        else:
            nginx_config = f"""server {{
    listen 80;
    server_name {domain};
    
    location / {{
        proxy_pass http://localhost:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}"""

        with open(config_path, "w") as f:
            f.write(nginx_config)

        # Enable site
        enabled_path = f"{CONFIG['nginx_sites_enabled']}/{domain}"
        if os.path.exists(enabled_path):
            os.remove(enabled_path)
        os.symlink(config_path, enabled_path)

        # Test and reload
        if test_nginx_config():
            subprocess.run(["systemctl", "reload", "nginx"], capture_output=True)

        return config_path

    except Exception as e:
        logger.error(f"Failed to create nginx config: {e}")
        return None


def create_subdomain(subdomain, parent_domain, app_name, port):
    """Create a subdomain"""
    try:
        if not validate_subdomain(subdomain):
            return {"success": False, "error": "Invalid subdomain format"}

        if parent_domain not in CONFIG["domains"]:
            return {"success": False, "error": "Invalid parent domain"}

        full_domain = f"{subdomain}.{parent_domain}"

        # Check if exists
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM domains WHERE domain_name = ?", (full_domain,)
        )
        if cursor.fetchone()[0] > 0:
            conn.close()
            return {"success": False, "error": "Domain already exists"}

        # Check for SSL
        cert_check = check_certificate_for_domain(full_domain)
        ssl_enabled = cert_check["available"]
        ssl_cert = cert_check.get("certificate")

        # Create nginx config
        nginx_path = create_nginx_config(
            full_domain, port, app_name, ssl_enabled, ssl_cert
        )

        # Save to database
        cursor.execute(
            """
            INSERT INTO domains 
            (domain_name, domain_type, parent_domain, port, app_name, 
             nginx_config_path, ssl_enabled, ssl_certificate_id, status)
            VALUES (?, 'subdomain', ?, ?, ?, ?, ?, ?, 'active')
        """,
            (
                full_domain,
                parent_domain,
                port,
                app_name,
                nginx_path,
                ssl_enabled,
                ssl_cert["id"] if ssl_cert else None,
            ),
        )

        # Log deployment
        cursor.execute(
            """
            INSERT INTO deployment_logs (domain_name, action, status, message)
            VALUES (?, 'deploy', 'success', 'Subdomain created successfully')
        """,
            (full_domain,),
        )

        conn.commit()
        conn.close()

        logger.info(f"✅ Created subdomain: {full_domain}")
        return {
            "success": True,
            "domain": full_domain,
            "port": port,
            "ssl_enabled": ssl_enabled,
            "url": f"http{'s' if ssl_enabled else ''}://{full_domain}",
        }

    except Exception as e:
        logger.error(f"Failed to create subdomain: {e}")
        return {"success": False, "error": str(e)}


def create_root_domain(domain_name, app_name, port):
    """Create a root domain"""
    try:
        # Check if exists
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM domains WHERE domain_name = ?", (domain_name,)
        )
        if cursor.fetchone()[0] > 0:
            conn.close()
            return {"success": False, "error": "Domain already exists"}

        # Check for SSL
        cert_check = check_certificate_for_domain(domain_name)
        ssl_enabled = cert_check["available"]
        ssl_cert = cert_check.get("certificate")

        # Create nginx config
        nginx_path = create_nginx_config(
            domain_name, port, app_name, ssl_enabled, ssl_cert
        )

        # Save to database
        cursor.execute(
            """
            INSERT INTO domains 
            (domain_name, domain_type, port, app_name, nginx_config_path, 
             ssl_enabled, ssl_certificate_id, status)
            VALUES (?, 'root', ?, ?, ?, ?, ?, 'active')
        """,
            (
                domain_name,
                port,
                app_name,
                nginx_path,
                ssl_enabled,
                ssl_cert["id"] if ssl_cert else None,
            ),
        )

        # Log deployment
        cursor.execute(
            """
            INSERT INTO deployment_logs (domain_name, action, status, message)
            VALUES (?, 'deploy', 'success', 'Root domain created successfully')
        """,
            (domain_name,),
        )

        conn.commit()
        conn.close()

        logger.info(f"✅ Created root domain: {domain_name}")
        return {
            "success": True,
            "domain": domain_name,
            "port": port,
            "ssl_enabled": ssl_enabled,
            "url": f"http{'s' if ssl_enabled else ''}://{domain_name}",
        }

    except Exception as e:
        logger.error(f"Failed to create root domain: {e}")
        return {"success": False, "error": str(e)}


def list_domains():
    """List all domains"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT domain_name, domain_type, parent_domain, port, app_name, 
                   ssl_enabled, status, created_at
            FROM domains 
            WHERE status = 'active'
            ORDER BY created_at DESC
        """
        )
        results = cursor.fetchall()
        conn.close()

        return [
            {
                "domain_name": r[0],
                "domain_type": r[1],
                "parent_domain": r[2],
                "port": r[3],
                "app_name": r[4],
                "ssl_enabled": bool(r[5]),
                "status": r[6],
                "created_at": r[7],
            }
            for r in results
        ]
    except Exception as e:
        logger.error(f"Failed to list domains: {e}")
        return []


def delete_domain(domain):
    """Delete a domain"""
    try:
        if not IS_READONLY:
            # Remove nginx config
            config_path = f"{CONFIG['nginx_sites_available']}/{domain}"
            enabled_path = f"{CONFIG['nginx_sites_enabled']}/{domain}"

            if os.path.exists(enabled_path):
                os.remove(enabled_path)
            if os.path.exists(config_path):
                os.remove(config_path)

            subprocess.run(["systemctl", "reload", "nginx"], capture_output=True)

        # Update database
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE domains SET status = 'removed', updated_at = CURRENT_TIMESTAMP 
            WHERE domain_name = ?
        """,
            (domain,),
        )

        cursor.execute(
            """
            INSERT INTO deployment_logs (domain_name, action, status, message)
            VALUES (?, 'remove', 'success', 'Domain removed successfully')
        """,
            (domain,),
        )

        conn.commit()
        conn.close()

        logger.info(f"✅ Deleted domain: {domain}")
        return {"success": True, "message": f"Domain {domain} deleted"}

    except Exception as e:
        logger.error(f"Failed to delete domain: {e}")
        return {"success": False, "error": str(e)}


def get_domain_suggestions(app_name):
    """Get domain suggestions"""
    suggestions = []

    for domain_name in CONFIG["domains"].keys():
        conn = get_db()
        cursor = conn.cursor()

        # Check root domain
        cursor.execute(
            "SELECT COUNT(*) FROM domains WHERE domain_name = ?", (domain_name,)
        )
        root_taken = cursor.fetchone()[0] > 0

        if not root_taken:
            suggestions.append(
                {
                    "domain": domain_name,
                    "type": "root",
                    "available": True,
                    "priority": 1,
                }
            )

        # Check subdomain
        subdomain = f"{app_name.lower()}.{domain_name}"
        cursor.execute(
            "SELECT COUNT(*) FROM domains WHERE domain_name = ?", (subdomain,)
        )
        sub_taken = cursor.fetchone()[0] > 0
        conn.close()

        if not sub_taken:
            suggestions.append(
                {
                    "domain": subdomain,
                    "type": "subdomain",
                    "subdomain": app_name.lower(),
                    "parent_domain": domain_name,
                    "available": True,
                    "priority": 2 if not root_taken else 1,
                }
            )

    suggestions.sort(key=lambda x: x["priority"])
    return {"success": True, "suggestions": suggestions}


# ============================================================================
# SYSTEM STATUS
# ============================================================================


def check_service_status(service_name):
    """Check if a service is running"""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_name], capture_output=True, text=True
        )
        return result.returncode == 0
    except:
        return False


def get_system_status():
    """Get system status"""
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM domains WHERE status = "active"')
        domain_count = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM ssl_certificates WHERE status = "active"')
        ssl_count = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM processes WHERE status = "running"')
        active_apps = cursor.fetchone()[0]

        conn.close()

        return {
            "nginx_running": check_service_status("nginx"),
            "database_connected": True,
            "domain_count": domain_count,
            "ssl_count": ssl_count,
            "active_apps": active_apps,
            "readonly_filesystem": IS_READONLY,
            "web_root": CONFIG["web_root"],
            "database_path": CONFIG["database_path"],
        }
    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        return {"error": str(e)}


# ============================================================================
# FLASK API
# ============================================================================

# Initialize database
ensure_database()

# Run first-time setup if needed
if is_first_run():
    logger.info("🔧 First deployment detected...")
    run_first_time_setup()

# Create Flask app
app = Flask(__name__)
CORS(app)


@app.route("/api/health")
def health():
    return jsonify(
        {
            "status": "healthy",
            "database": os.path.exists(CONFIG["database_path"]),
            "readonly_mode": IS_READONLY,
            "timestamp": datetime.utcnow().isoformat(),
        }
    )


@app.route("/api/status")
def status():
    try:
        return jsonify({"success": True, **get_system_status()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/domains")
def get_domains():
    domains = list_domains()
    return jsonify({"success": True, "domains": domains, "count": len(domains)})


@app.route("/api/domains/available")
def available_domains():
    return jsonify(CONFIG["domains"])


@app.route("/api/domains/suggestions", methods=["POST"])
def domain_suggestions():
    data = request.get_json()
    app_name = data.get("app_name")
    if not app_name:
        return jsonify({"error": "app_name required"}), 400
    return jsonify(get_domain_suggestions(app_name))


@app.route("/api/domains", methods=["POST"])
def create_domain():
    try:
        data = request.get_json()
        domain_type = data.get("domain_type", "subdomain")

        if domain_type == "root":
            result = create_root_domain(
                data["domain_name"], data["app_name"], data["port"]
            )
        else:
            result = create_subdomain(
                data["subdomain"], data["parent_domain"], data["app_name"], data["port"]
            )

        return jsonify(result), 200 if result.get("success") else 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/domains/<domain>", methods=["DELETE"])
def remove_domain(domain):
    result = delete_domain(domain)
    return jsonify(result), 200 if result.get("success") else 404


@app.route("/api/ssl/certificates")
def get_certificates():
    certs = list_certificates()
    return jsonify({"success": True, "certificates": certs})


@app.route("/api/ssl/certificates", methods=["POST"])
def create_certificate():
    data = request.get_json()
    result = install_certificate(data["domain"], data.get("certificate_type", "single"))
    return jsonify(result), 200 if result.get("success") else 400


@app.route("/api/ssl/certificates/<domain>")
def get_certificate(domain):
    cert = get_certificate_info(domain)
    if cert:
        return jsonify({"success": True, "certificate": cert})
    return jsonify({"error": "Certificate not found"}), 404


@app.route("/api/logs")
def get_logs():
    try:
        limit = request.args.get("limit", 100, type=int)
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT domain_name, action, status, message, created_at 
            FROM deployment_logs 
            ORDER BY created_at DESC LIMIT ?
        """,
            (limit,),
        )

        logs = [
            {
                "domain_name": r[0],
                "action": r[1],
                "status": r[2],
                "message": r[3],
                "created_at": r[4],
            }
            for r in cursor.fetchall()
        ]

        conn.close()
        return jsonify({"success": True, "logs": logs})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    logger.info(f"🚀 Starting Complete Hosting Manager on {args.host}:{args.port}")
    logger.info(f"   Read-only mode: {IS_READONLY}")
    logger.info(f"   Database: {CONFIG['database_path']}")
    logger.info(f"   Web root: {CONFIG['web_root']}")

    app.run(host=args.host, port=args.port, debug=args.debug)
