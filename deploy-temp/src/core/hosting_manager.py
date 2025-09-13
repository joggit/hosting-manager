# src/core/hosting_manager.py
"""
Core hosting management functionality
Handles domain deployment, nginx configuration, and process management
"""

import os
import subprocess
import sqlite3
import shutil
import time
import json
import pwd
import grp
from datetime import datetime
from pathlib import Path


class HostingManager:
    """Core hosting management class"""

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.is_root = os.geteuid() == 0
        self.current_user = self._get_current_user()
        self.readonly_filesystem = self._detect_readonly_filesystem()
        self._setup_readonly_config()

    def _get_current_user(self):
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

    def _detect_readonly_filesystem(self):
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
            self.logger.info("Read-only filesystem detected - using safe mode")

        return is_readonly

    def _setup_readonly_config(self):
        """Configure for read-only filesystem"""
        if self.readonly_filesystem:
            # Update config for writable locations
            self.config.update(
                {
                    "database_path": "/tmp/hosting/hosting.db",
                    "web_root": "/tmp/www/domains",
                    "log_dir": "/tmp/hosting/logs",
                    "readonly_mode": True,
                }
            )

            # Create writable directories
            writable_dirs = [
                "/tmp/hosting",
                "/tmp/www/domains",
                "/tmp/hosting/logs",
                "/tmp/nodejs-apps",
                "/tmp/pm2-home",
            ]

            for directory in writable_dirs:
                try:
                    os.makedirs(directory, mode=0o755, exist_ok=True)
                    self.logger.debug(f"Created writable directory: {directory}")
                except Exception as e:
                    self.logger.warning(f"Could not create {directory}: {e}")

    def setup_system(self):
        """Setup the complete hosting system"""
        self.logger.info("Starting hosting system setup...")

        if not self.is_root:
            self.logger.error("Root privileges required for setup")
            return False

        try:
            # Install dependencies
            if not self._install_dependencies():
                return False

            # Setup database
            if not self._setup_database():
                return False

            # Setup nginx
            if not self._setup_nginx():
                return False

            # Setup PM2 if available
            self._setup_pm2()

            # Create systemd service - FIXED VERSION
            if not self.readonly_filesystem:
                self._create_systemd_service()

            self.logger.info("System setup completed successfully")
            return True

        except Exception as e:
            self.logger.error(f"System setup failed: {e}")
            return False

    def _install_dependencies(self):
        """Install required system dependencies"""
        if self.readonly_filesystem:
            self.logger.info("Read-only mode - skipping package installation")
            return True

        self.logger.info("Installing system dependencies...")

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

        try:
            # Update package list
            result = subprocess.run(["apt", "update"], capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error("Failed to update package list")
                return False

            # Install packages
            result = subprocess.run(
                ["apt", "install", "-y"] + packages, capture_output=True, text=True
            )
            if result.returncode != 0:
                self.logger.error(f"Package installation failed: {result.stderr}")
                return False

            # Install Python packages
            python_packages = ["flask", "flask-cors", "gunicorn", "psutil", "requests"]
            for package in python_packages:
                result = subprocess.run(
                    ["pip3", "install", package], capture_output=True, text=True
                )
                if result.returncode == 0:
                    self.logger.debug(f"Installed {package}")
                else:
                    self.logger.warning(f"Failed to install {package}")

            # Install PM2 globally
            result = subprocess.run(
                ["npm", "install", "-g", "pm2"], capture_output=True, text=True
            )
            if result.returncode == 0:
                self.logger.info("PM2 installed successfully")
            else:
                self.logger.warning(
                    "PM2 installation failed - using alternative process management"
                )

            return True

        except Exception as e:
            self.logger.error(f"Dependency installation failed: {e}")
            return False

    def _setup_database(self):
        """Initialize SQLite database"""
        try:
            db_path = self.config.get("database_path")
            db_dir = os.path.dirname(db_path)

            os.makedirs(db_dir, mode=0o755, exist_ok=True)

            conn = sqlite3.connect(db_path)

            # Optimize database settings
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA cache_size=10000")
            conn.execute("PRAGMA foreign_keys=ON")

            cursor = conn.cursor()

            # Create tables
            cursor.executescript(
                """
                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_name TEXT UNIQUE NOT NULL,
                    port INTEGER NOT NULL,
                    site_type TEXT DEFAULT 'static',
                    ssl_enabled BOOLEAN DEFAULT 0,
                    status TEXT DEFAULT 'active',
                    process_manager TEXT DEFAULT 'systemd',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (domain_name) REFERENCES domains (domain_name)
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

            self.logger.info("Database setup completed")
            return True

        except Exception as e:
            self.logger.error(f"Database setup failed: {e}")
            return False

    def _setup_nginx(self):
        """Setup nginx configuration"""
        try:
            if self.readonly_filesystem:
                self.logger.info("Read-only mode - nginx setup limited")
                return True

            # Create nginx directories
            os.makedirs("/etc/nginx/sites-available", exist_ok=True)
            os.makedirs("/etc/nginx/sites-enabled", exist_ok=True)

            # Remove default site
            default_site = "/etc/nginx/sites-enabled/default"
            if os.path.exists(default_site):
                os.remove(default_site)

            # Test nginx config
            if not self._test_nginx_config():
                self.logger.error("Nginx configuration test failed")
                return False

            # Enable and start nginx
            subprocess.run(["systemctl", "enable", "nginx"], capture_output=True)
            subprocess.run(["systemctl", "start", "nginx"], capture_output=True)

            self.logger.info("Nginx setup completed")
            return True

        except Exception as e:
            self.logger.error(f"Nginx setup failed: {e}")
            return False

    def _setup_pm2(self):
        """Setup PM2 process manager"""
        try:
            # Check if PM2 is available
            result = subprocess.run(
                ["pm2", "--version"], capture_output=True, text=True
            )

            if result.returncode == 0:
                self.logger.info(f"PM2 version {result.stdout.strip()} detected")

                # Setup PM2 for www-data user
                pm2_home = (
                    "/tmp/pm2-home"
                    if self.readonly_filesystem
                    else "/home/www-data/.pm2"
                )
                os.makedirs(pm2_home, mode=0o755, exist_ok=True)

                # Configure PM2 environment
                os.environ["PM2_HOME"] = pm2_home

                self.logger.info("PM2 setup completed")
                return True
            else:
                self.logger.warning(
                    "PM2 not available - using alternative process management"
                )
                return False

        except Exception as e:
            self.logger.warning(f"PM2 setup failed: {e}")
            return False

    def _test_nginx_config(self):
        """Test nginx configuration"""
        try:
            result = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def _create_systemd_service(self):
        """Create systemd service for the API - FIXED VERSION"""
        if self.readonly_filesystem:
            return True

        try:
            # FIXED: Point to the correct main script location
            main_script_path = "/opt/hosting-manager/hosting_manager.py"
            working_directory = "/opt/hosting-manager"

            service_content = f"""[Unit]
Description=Hosting Manager API v3.0
After=network.target nginx.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory={working_directory}
Environment=PYTHONPATH={working_directory}
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 {main_script_path} --api
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""

            with open("/etc/systemd/system/hosting-manager.service", "w") as f:
                f.write(service_content)

            subprocess.run(["systemctl", "daemon-reload"], capture_output=True)

            self.logger.info("Systemd service created")
            return True

        except Exception as e:
            self.logger.error(f"Failed to create systemd service: {e}")
            return False

    def get_database_connection(self):
        """Get database connection"""
        try:
            db_path = self.config.get("database_path")
            conn = sqlite3.connect(db_path, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            return conn
        except Exception as e:
            self.logger.error(f"Database connection failed: {e}")
            return None

    def deploy_domain(self, domain_name, port, site_type="static", app_name=None):
        """Deploy a new domain with optional app association"""
        try:
            self.logger.info(f"Deploying domain: {domain_name}")

            # Create domain directory
            domain_path = f"{self.config.get('web_root')}/{domain_name}"
            public_path = f"{domain_path}/public"

            os.makedirs(public_path, mode=0o755, exist_ok=True)

            # Create default index.html
            self._create_default_index(domain_name, public_path, port, site_type)

            # Configure nginx
            if not self.readonly_filesystem:
                if not self._configure_nginx_site(
                    domain_name, public_path, port, site_type
                ):
                    return False

            # Add to database with app_name
            self._add_domain_to_db(domain_name, port, site_type, app_name)

            self.logger.info(f"Domain {domain_name} deployed successfully")
            return True

        except Exception as e:
            self.logger.error(f"Domain deployment failed: {e}")
            return False

    def _create_default_index(self, domain_name, public_path, port, site_type):
        """Create default index.html"""
        index_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{domain_name} - Live</title>
    <style>
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; text-align: center; padding: 50px; min-height: 100vh;
            display: flex; align-items: center; justify-content: center; margin: 0;
        }}
        .container {{ max-width: 800px; }}
        h1 {{ font-size: 3em; margin-bottom: 0.5em; }}
        .info {{ 
            background: rgba(255,255,255,0.1); 
            padding: 20px; border-radius: 10px; margin-top: 20px;
        }}
        .status {{ margin-top: 20px; }}
        .status div {{ 
            display: inline-block; margin: 10px; padding: 10px; 
            background: rgba(255,255,255,0.1); border-radius: 5px; 
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{domain_name}</h1>
        <div class="info">
            <p>Your domain is successfully deployed!</p>
            <div class="status">
                <div><strong>Type:</strong> {site_type.title()}</div>
                <div><strong>Port:</strong> {port}</div>
                <div><strong>Status:</strong> Active</div>
            </div>
            <p style="margin-top: 20px; font-size: 0.9em;">
                Replace this file: {public_path}/index.html
            </p>
        </div>
    </div>
</body>
</html>"""

        with open(f"{public_path}/index.html", "w") as f:
            f.write(index_html)

    def _configure_nginx_site(self, domain_name, public_path, port, site_type):
        """Configure nginx for the site"""
        try:
            nginx_config = self._generate_nginx_config(
                domain_name, public_path, port, site_type
            )

            config_path = f"/etc/nginx/sites-available/{domain_name}"
            enabled_path = f"/etc/nginx/sites-enabled/{domain_name}"

            # Write config
            with open(config_path, "w") as f:
                f.write(nginx_config)

            # Enable site
            if os.path.exists(enabled_path):
                os.remove(enabled_path)
            os.symlink(config_path, enabled_path)

            # Test and reload
            if self._test_nginx_config():
                subprocess.run(["systemctl", "reload", "nginx"], capture_output=True)
                self.logger.info(f"Nginx configured for {domain_name}")
                return True
            else:
                self.logger.error("Nginx config test failed")
                return False

        except Exception as e:
            self.logger.error(f"Nginx configuration failed: {e}")
            return False

    def _generate_nginx_config(self, domain_name, public_path, port, site_type):
        """Generate nginx configuration"""
        if site_type == "static":
            return f"""server {{
    listen 80;
    server_name {domain_name};
    root {public_path};
    index index.html;
    
    location / {{
        try_files $uri $uri/ =404;
    }}
    
    location ~* \\.(css|js|png|jpg|jpeg|gif|ico|svg)$ {{
        expires 1y;
        add_header Cache-Control "public, immutable";
    }}
}}"""
        else:
            return f"""server {{
    listen 80;
    server_name {domain_name};
    
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

    def _add_domain_to_db(self, domain_name, port, site_type, app_name=None):
        """Add domain to database with optional app_name"""
        try:
            conn = self.get_database_connection()
            if conn:
                cursor = conn.cursor()

                # Check if app_name column exists (backward compatibility)
                cursor.execute("PRAGMA table_info(domains)")
                columns = [row[1] for row in cursor.fetchall()]

                if "app_name" in columns:
                    # Use new schema with app_name
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO domains 
                        (domain_name, port, site_type, ssl_enabled, status, app_name, updated_at)
                        VALUES (?, ?, ?, 0, 'active', ?, CURRENT_TIMESTAMP)
                    """,
                        (domain_name, port, site_type, app_name),
                    )
                else:
                    # Use old schema without app_name (fallback)
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO domains 
                        (domain_name, port, site_type, ssl_enabled, status, updated_at)
                        VALUES (?, ?, ?, 0, 'active', CURRENT_TIMESTAMP)
                    """,
                        (domain_name, port, site_type),
                    )

                cursor.execute(
                    """
                    INSERT INTO deployment_logs 
                    (domain_name, action, status, message)
                    VALUES (?, 'deploy', 'success', 'Domain deployed successfully')
                """,
                    (domain_name,),
                )

                conn.commit()
                conn.close()

        except Exception as e:
            self.logger.error(f"Database update failed: {e}")

    def create_domain_with_app(self, domain_name, port, app_name):
        """Create domain configuration with app association"""
        try:
            # Deploy domain with app association
            success = self.deploy_domain(domain_name, port, "node", app_name)

            if success:
                return {
                    "success": True,
                    "message": f"Domain {domain_name} created for app {app_name}",
                }
            else:
                return {"success": False, "error": "Failed to create domain"}
        except Exception as e:
            self.logger.error(f"Failed to create domain with app: {e}")
            return {"success": False, "error": str(e)}

    def list_domains_with_apps(self):
        """List all domains with their associated apps"""
        try:
            conn = self.get_database_connection()
            if not conn:
                self.logger.error("Database connection failed")
                return []

            cursor = conn.cursor()

            # Check if app_name column exists
            cursor.execute("PRAGMA table_info(domains)")
            columns = [row[1] for row in cursor.fetchall()]

            if "app_name" in columns:
                cursor.execute(
                    """
                    SELECT domain_name, port, site_type, ssl_enabled, status, app_name, created_at
                    FROM domains 
                    WHERE status = 'active'
                    ORDER BY created_at DESC
                """
                )

                domains = cursor.fetchall()
                conn.close()

                return [
                    {
                        "domain_name": row[0],
                        "port": row[1],
                        "site_type": row[2],
                        "ssl_enabled": bool(row[3]),
                        "status": row[4],
                        "app_name": row[5],
                        "created_at": row[6],
                    }
                    for row in domains
                ]
            else:
                # Fallback to original method if column doesn't exist
                return self.list_domains()

        except Exception as e:
            self.logger.error(f"Failed to list domains with apps: {e}")
            return []

    def remove_domain(self, domain_name):
        """Remove a domain"""
        try:
            self.logger.info(f"Removing domain: {domain_name}")

            # Stop any running processes
            self._stop_domain_processes(domain_name)

            # Remove nginx config
            if not self.readonly_filesystem:
                self._remove_nginx_config(domain_name)

            # Update database
            conn = self.get_database_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE domains SET status = 'removed', updated_at = CURRENT_TIMESTAMP WHERE domain_name = ?",
                    (domain_name,),
                )
                cursor.execute(
                    """
                    INSERT INTO deployment_logs 
                    (domain_name, action, status, message)
                    VALUES (?, 'remove', 'success', 'Domain removed successfully')
                """,
                    (domain_name,),
                )
                conn.commit()
                conn.close()

            self.logger.info(f"Domain {domain_name} removed successfully")
            return True

        except Exception as e:
            self.logger.error(f"Domain removal failed: {e}")
            return False

    def _stop_domain_processes(self, domain_name):
        """Stop all processes associated with a domain"""
        try:
            conn = self.get_database_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT name, process_manager FROM processes WHERE domain_name = ? AND status = 'running'",
                    (domain_name,),
                )

                for row in cursor.fetchall():
                    process_name, process_manager = row
                    self._stop_process(process_name, process_manager)

                conn.close()

        except Exception as e:
            self.logger.error(f"Failed to stop domain processes: {e}")

    def _stop_process(self, process_name, process_manager):
        """Stop a specific process"""
        try:
            if process_manager == "pm2":
                result = subprocess.run(
                    ["pm2", "stop", process_name], capture_output=True
                )
                return result.returncode == 0
            elif process_manager == "systemd":
                result = subprocess.run(
                    ["systemctl", "stop", f"nodejs-{process_name}"], capture_output=True
                )
                return result.returncode == 0
            elif process_manager == "readonly-simple":
                script_path = f"/tmp/nodejs-apps/{process_name}/control.sh"
                if os.path.exists(script_path):
                    result = subprocess.run([script_path, "stop"], capture_output=True)
                    return result.returncode == 0

        except Exception as e:
            self.logger.error(f"Failed to stop process {process_name}: {e}")
            return False

    def _remove_nginx_config(self, domain_name):
        """Remove nginx configuration"""
        try:
            config_path = f"/etc/nginx/sites-available/{domain_name}"
            enabled_path = f"/etc/nginx/sites-enabled/{domain_name}"

            if os.path.exists(enabled_path):
                os.remove(enabled_path)
            if os.path.exists(config_path):
                os.remove(config_path)

            # Reload nginx
            subprocess.run(["systemctl", "reload", "nginx"], capture_output=True)

        except Exception as e:
            self.logger.error(f"Failed to remove nginx config: {e}")

    def list_domains(self):
        """List all active domains"""
        try:
            conn = self.get_database_connection()
            if not conn:
                self.logger.error("Database connection failed")
                return []

            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT domain_name, port, site_type, ssl_enabled, status, created_at
                FROM domains 
                WHERE status = 'active'
                ORDER BY created_at DESC
            """
            )

            domains = cursor.fetchall()
            conn.close()

            return [
                {
                    "domain_name": row[0],
                    "port": row[1],
                    "site_type": row[2],
                    "ssl_enabled": bool(row[3]),
                    "status": row[4],
                    "created_at": row[5],
                }
                for row in domains
            ]

        except Exception as e:
            self.logger.error(f"Failed to list domains: {e}")
            return []

    def get_system_status(self):
        """Get overall system status"""
        try:
            conn = self.get_database_connection()
            status = {
                "nginx_running": self._check_service_status("nginx"),
                "database_connected": conn is not None,
                "domain_count": 0,
                "ssl_count": 0,
                "active_apps": 0,
                "readonly_filesystem": self.readonly_filesystem,
                "web_root": self.config.get("web_root"),
                "database_path": self.config.get("database_path"),
            }

            if conn:
                cursor = conn.cursor()

                # Count domains
                cursor.execute("SELECT COUNT(*) FROM domains WHERE status = 'active'")
                status["domain_count"] = cursor.fetchone()[0]

                # Count SSL enabled
                cursor.execute("SELECT COUNT(*) FROM domains WHERE ssl_enabled = 1")
                status["ssl_count"] = cursor.fetchone()[0]

                # Count running processes
                cursor.execute(
                    "SELECT COUNT(*) FROM processes WHERE status = 'running'"
                )
                status["active_apps"] = cursor.fetchone()[0]

                conn.close()

            return status

        except Exception as e:
            self.logger.error(f"Failed to get system status: {e}")
            return {"error": str(e)}

    def _check_service_status(self, service_name):
        """Check if a systemd service is running"""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", service_name], capture_output=True, text=True
            )
            return result.returncode == 0
        except:
            return False
