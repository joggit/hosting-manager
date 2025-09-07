# src/hosting/domain_manager.py
"""
Domain and subdomain management for multi-tenant hosting
Handles nginx configuration, SSL, and DNS management
"""

import os
import json
import subprocess
import sqlite3
import re
from datetime import datetime
from pathlib import Path


class DomainManager:
    """Manage domains, subdomains, and nginx configurations"""

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.nginx_config_path = "/etc/nginx/sites-available"
        self.nginx_enabled_path = "/etc/nginx/sites-enabled"
        self.ssl_cert_path = "/etc/letsencrypt/live"

        # Available domains configuration
        self.available_domains = {
            "smartwave.co.za": {
                "name": "SmartWave",
                "description": "Technology & Innovation Platform",
                "port_range": (3000, 3099),
                "ssl_enabled": True,
                "wildcard_ssl": True,
            },
            "datablox.co.za": {
                "name": "DataBlox",
                "description": "Data Analytics & Business Intelligence",
                "port_range": (3100, 3199),
                "ssl_enabled": True,
                "wildcard_ssl": True,
            },
            "mondaycafe.co.za": {
                "name": "Monday Cafe",
                "description": "Food, Events & Hospitality",
                "port_range": (3200, 3299),
                "ssl_enabled": True,
                "wildcard_ssl": True,
            },
        }

    def setup_database(self, db_connection):
        """Setup domain management tables"""
        try:
            cursor = db_connection.cursor()

            # Domains table
            cursor.execute(
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
                    ssl_cert_path TEXT,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Domain allocations table for tracking port usage
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS domain_allocations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    parent_domain TEXT NOT NULL,
                    allocated_ports TEXT, -- JSON array of allocated ports
                    next_available_port INTEGER,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Initialize domain allocations for each parent domain
            for domain, config in self.available_domains.items():
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO domain_allocations (parent_domain, allocated_ports, next_available_port)
                    VALUES (?, ?, ?)
                """,
                    (domain, json.dumps([]), config["port_range"][0]),
                )

            db_connection.commit()
            self.logger.info("Domain management database initialized")
            return True

        except Exception as e:
            self.logger.error(f"Failed to setup domain database: {e}")
            return False

    def get_available_domains(self):
        """Get list of available parent domains with their configurations"""
        return self.available_domains

    def get_available_subdomains(self, parent_domain, limit=50):
        """Get available subdomain suggestions for a parent domain"""
        if parent_domain not in self.available_domains:
            return []

        try:
            # Get existing subdomains
            conn = self.get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT domain_name FROM domains 
                WHERE parent_domain = ? AND status = 'active'
            """,
                (parent_domain,),
            )

            existing = [row[0].split(".")[0] for row in cursor.fetchall()]
            conn.close()

            # Generate suggestions
            suggestions = []
            common_prefixes = [
                "app",
                "api",
                "admin",
                "dashboard",
                "portal",
                "blog",
                "shop",
                "docs",
                "support",
                "demo",
                "staging",
                "dev",
                "test",
                "preview",
            ]

            for prefix in common_prefixes:
                if prefix not in existing:
                    suggestions.append(
                        {
                            "subdomain": prefix,
                            "full_domain": f"{prefix}.{parent_domain}",
                            "available": True,
                        }
                    )

            return suggestions[:limit]

        except Exception as e:
            self.logger.error(f"Failed to get available subdomains: {e}")
            return []

    def check_subdomain_availability(self, subdomain, parent_domain):
        """Check if a subdomain is available"""
        try:
            # Validate subdomain format
            if not self._validate_subdomain(subdomain):
                return False, "Invalid subdomain format"

            if parent_domain not in self.available_domains:
                return False, "Invalid parent domain"

            full_domain = f"{subdomain}.{parent_domain}"

            # Check database
            conn = self.get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT COUNT(*) FROM domains 
                WHERE domain_name = ? AND status IN ('active', 'pending')
            """,
                (full_domain,),
            )

            count = cursor.fetchone()[0]
            conn.close()

            if count > 0:
                return False, "Subdomain already exists"

            # Check nginx config exists
            nginx_config = f"{self.nginx_config_path}/{full_domain}"
            if os.path.exists(nginx_config):
                return False, "Nginx configuration already exists"

            return True, "Available"

        except Exception as e:
            self.logger.error(f"Failed to check subdomain availability: {e}")
            return False, "Error checking availability"

    def allocate_port(self, parent_domain):
        """Allocate next available port for a domain"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT allocated_ports, next_available_port FROM domain_allocations
                WHERE parent_domain = ?
            """,
                (parent_domain,),
            )

            result = cursor.fetchone()
            if not result:
                return None

            allocated_ports = json.loads(result[0])
            next_port = result[1]
            port_range = self.available_domains[parent_domain]["port_range"]

            # Find next available port
            while next_port in allocated_ports or next_port > port_range[1]:
                next_port += 1
                if next_port > port_range[1]:
                    conn.close()
                    return None  # No ports available

            # Allocate the port
            allocated_ports.append(next_port)

            cursor.execute(
                """
                UPDATE domain_allocations 
                SET allocated_ports = ?, next_available_port = ?, updated_at = CURRENT_TIMESTAMP
                WHERE parent_domain = ?
            """,
                (json.dumps(allocated_ports), next_port + 1, parent_domain),
            )

            conn.commit()
            conn.close()

            self.logger.info(f"Allocated port {next_port} for {parent_domain}")
            return next_port

        except Exception as e:
            self.logger.error(f"Failed to allocate port: {e}")
            return None

    def create_subdomain(self, subdomain, parent_domain, app_name, port=None):
        """Create a new subdomain with nginx configuration"""
        try:
            # Validate inputs
            available, message = self.check_subdomain_availability(
                subdomain, parent_domain
            )
            if not available:
                return {"success": False, "error": message}

            # Allocate port if not provided
            if port is None:
                port = self.allocate_port(parent_domain)
                if port is None:
                    return {"success": False, "error": "No available ports"}

            full_domain = f"{subdomain}.{parent_domain}"

            # Create nginx configuration
            nginx_config_path = self._create_nginx_config(full_domain, port, app_name)
            if not nginx_config_path:
                return {
                    "success": False,
                    "error": "Failed to create nginx configuration",
                }

            # Enable nginx site
            if not self._enable_nginx_site(full_domain):
                return {"success": False, "error": "Failed to enable nginx site"}

            # Setup SSL if enabled
            ssl_cert_path = None
            if self.available_domains[parent_domain]["ssl_enabled"]:
                ssl_cert_path = self._setup_ssl(full_domain, parent_domain)

            # Save to database
            conn = self.get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO domains (
                    domain_name, parent_domain, port, app_name, 
                    nginx_config_path, ssl_enabled, ssl_cert_path, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    full_domain,
                    parent_domain,
                    port,
                    app_name,
                    nginx_config_path,
                    ssl_cert_path is not None,
                    ssl_cert_path,
                    "active",
                ),
            )

            conn.commit()
            conn.close()

            # Reload nginx
            if self._reload_nginx():
                self.logger.info(f"Successfully created subdomain: {full_domain}")
                return {
                    "success": True,
                    "domain": full_domain,
                    "port": port,
                    "ssl_enabled": ssl_cert_path is not None,
                    "nginx_config": nginx_config_path,
                }
            else:
                return {"success": False, "error": "Failed to reload nginx"}

        except Exception as e:
            self.logger.error(f"Failed to create subdomain: {e}")
            return {"success": False, "error": str(e)}

    def _create_nginx_config(self, domain, port, app_name):
        """Create nginx configuration for subdomain"""
        try:
            config_path = f"{self.nginx_config_path}/{domain}"

            # Determine if SSL should be configured
            parent_domain = ".".join(domain.split(".")[1:])
            ssl_enabled = self.available_domains.get(parent_domain, {}).get(
                "ssl_enabled", False
            )

            if ssl_enabled:
                nginx_config = f"""
# Nginx configuration for {domain}
# App: {app_name}
# Port: {port}

server {{
    listen 80;
    server_name {domain};
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}}

server {{
    listen 443 ssl http2;
    server_name {domain};
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/{parent_domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{parent_domain}/privkey.pem;
    
    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Proxy to Next.js app
    location / {{
        proxy_pass http://localhost:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }}
    
    # Health check endpoint
    location /health {{
        access_log off;
        return 200 "healthy\\n";
        add_header Content-Type text/plain;
    }}
    
    # Block access to sensitive files
    location ~ /\\. {{
        deny all;
    }}
    
    location ~ /(package\\.json|package-lock\\.json|next\\.config\\.(js|mjs)|ecosystem\\.config\\.json)$ {{
        deny all;
    }}
}}
"""
            else:
                nginx_config = f"""
# Nginx configuration for {domain}
# App: {app_name}
# Port: {port}

server {{
    listen 80;
    server_name {domain};
    
    # Proxy to Next.js app
    location / {{
        proxy_pass http://localhost:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }}
    
    # Health check endpoint
    location /health {{
        access_log off;
        return 200 "healthy\\n";
        add_header Content-Type text/plain;
    }}
    
    # Block access to sensitive files
    location ~ /\\. {{
        deny all;
    }}
    
    location ~ /(package\\.json|package-lock\\.json|next\\.config\\.(js|mjs)|ecosystem\\.config\\.json)$ {{
        deny all;
    }}
}}
"""

            # Write configuration file
            with open(config_path, "w") as f:
                f.write(nginx_config)

            self.logger.info(f"Created nginx config: {config_path}")
            return config_path

        except Exception as e:
            self.logger.error(f"Failed to create nginx config: {e}")
            return None

    def _enable_nginx_site(self, domain):
        """Enable nginx site by creating symlink"""
        try:
            config_path = f"{self.nginx_config_path}/{domain}"
            enabled_path = f"{self.nginx_enabled_path}/{domain}"

            if os.path.exists(enabled_path):
                os.remove(enabled_path)

            os.symlink(config_path, enabled_path)
            self.logger.info(f"Enabled nginx site: {domain}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to enable nginx site: {e}")
            return False

    def _setup_ssl(self, domain, parent_domain):
        """Setup SSL certificate for subdomain"""
        try:
            # Check if wildcard certificate exists for parent domain
            wildcard_cert_path = f"{self.ssl_cert_path}/{parent_domain}"

            if os.path.exists(wildcard_cert_path):
                self.logger.info(f"Using existing wildcard SSL for {domain}")
                return wildcard_cert_path

            # If no wildcard cert, try to get one for the specific subdomain
            result = subprocess.run(
                [
                    "certbot",
                    "certonly",
                    "--nginx",
                    "-d",
                    domain,
                    "--non-interactive",
                    "--agree-tos",
                    "--email",
                    self.config.get("ssl_email", "admin@localhost"),
                ],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                cert_path = f"{self.ssl_cert_path}/{domain}"
                self.logger.info(f"SSL certificate obtained for {domain}")
                return cert_path
            else:
                self.logger.warning(
                    f"Failed to obtain SSL for {domain}: {result.stderr}"
                )
                return None

        except Exception as e:
            self.logger.error(f"SSL setup failed for {domain}: {e}")
            return None

    def _reload_nginx(self):
        """Reload nginx configuration"""
        try:
            # Test nginx configuration first
            test_result = subprocess.run(
                ["nginx", "-t"], capture_output=True, text=True
            )

            if test_result.returncode != 0:
                self.logger.error(f"Nginx config test failed: {test_result.stderr}")
                return False

            # Reload nginx
            reload_result = subprocess.run(
                ["systemctl", "reload", "nginx"], capture_output=True, text=True
            )

            if reload_result.returncode == 0:
                self.logger.info("Nginx reloaded successfully")
                return True
            else:
                self.logger.error(f"Nginx reload failed: {reload_result.stderr}")
                return False

        except Exception as e:
            self.logger.error(f"Failed to reload nginx: {e}")
            return False

    def _validate_subdomain(self, subdomain):
        """Validate subdomain format"""
        # RFC 1123 hostname rules
        if not subdomain or len(subdomain) > 63:
            return False

        # Must start and end with alphanumeric
        if not (subdomain[0].isalnum() and subdomain[-1].isalnum()):
            return False

        # Can contain hyphens but not consecutive ones
        if "--" in subdomain:
            return False

        # Only alphanumeric and hyphens
        if not re.match(r"^[a-zA-Z0-9-]+$", subdomain):
            return False

        # Reserved subdomains
        reserved = ["www", "mail", "ftp", "localhost", "api", "admin", "root", "test"]
        if subdomain.lower() in reserved:
            return False

        return True

    def get_domain_info(self, domain):
        """Get information about a specific domain"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM domains WHERE domain_name = ?
            """,
                (domain,),
            )

            result = cursor.fetchone()
            conn.close()

            if result:
                return {
                    "domain_name": result[1],
                    "parent_domain": result[3],
                    "port": result[4],
                    "app_name": result[5],
                    "ssl_enabled": result[7],
                    "status": result[9],
                    "created_at": result[10],
                }
            return None

        except Exception as e:
            self.logger.error(f"Failed to get domain info: {e}")
            return None

    def list_domains(self, parent_domain=None, status=None):
        """List all domains with optional filtering"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            query = "SELECT * FROM domains WHERE 1=1"
            params = []

            if parent_domain:
                query += " AND parent_domain = ?"
                params.append(parent_domain)

            if status:
                query += " AND status = ?"
                params.append(status)

            query += " ORDER BY created_at DESC"

            cursor.execute(query, params)
            results = cursor.fetchall()
            conn.close()

            domains = []
            for row in results:
                domains.append(
                    {
                        "id": row[0],
                        "domain_name": row[1],
                        "parent_domain": row[3],
                        "port": row[4],
                        "app_name": row[5],
                        "ssl_enabled": row[7],
                        "status": row[9],
                        "created_at": row[10],
                    }
                )

            return domains

        except Exception as e:
            self.logger.error(f"Failed to list domains: {e}")
            return []

    def delete_subdomain(self, domain):
        """Delete a subdomain and its configuration"""
        try:
            # Get domain info
            domain_info = self.get_domain_info(domain)
            if not domain_info:
                return {"success": False, "error": "Domain not found"}

            # Remove nginx configuration
            config_path = f"{self.nginx_config_path}/{domain}"
            enabled_path = f"{self.nginx_enabled_path}/{domain}"

            if os.path.exists(enabled_path):
                os.remove(enabled_path)

            if os.path.exists(config_path):
                os.remove(config_path)

            # Free up the port
            parent_domain = domain_info["parent_domain"]
            port = domain_info["port"]

            conn = self.get_db_connection()
            cursor = conn.cursor()

            # Remove port from allocated ports
            cursor.execute(
                """
                SELECT allocated_ports FROM domain_allocations
                WHERE parent_domain = ?
            """,
                (parent_domain,),
            )

            result = cursor.fetchone()
            if result:
                allocated_ports = json.loads(result[0])
                if port in allocated_ports:
                    allocated_ports.remove(port)

                    cursor.execute(
                        """
                        UPDATE domain_allocations 
                        SET allocated_ports = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE parent_domain = ?
                    """,
                        (json.dumps(allocated_ports), parent_domain),
                    )

            # Remove domain record
            cursor.execute("DELETE FROM domains WHERE domain_name = ?", (domain,))

            conn.commit()
            conn.close()

            # Reload nginx
            self._reload_nginx()

            self.logger.info(f"Deleted subdomain: {domain}")
            return {
                "success": True,
                "message": f"Subdomain {domain} deleted successfully",
            }

        except Exception as e:
            self.logger.error(f"Failed to delete subdomain: {e}")
            return {"success": False, "error": str(e)}

    def get_db_connection(self):
        """Get database connection"""
        # This should use the same connection as the hosting manager
        db_path = self.config.get("database_path", "/tmp/hosting.db")
        return sqlite3.connect(db_path, timeout=30.0)
