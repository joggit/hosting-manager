# src/hosting/domain_manager.py - Updated with SSL Certificate Manager integration
"""
Domain and subdomain management for multi-tenant hosting
Handles nginx configuration with centralized SSL management
"""

import os
import json
import subprocess
import sqlite3
import re
from datetime import datetime
from pathlib import Path


class DomainManager:
    """Manage domains, subdomains, and nginx configurations with centralized SSL"""

    def __init__(self, config, logger, ssl_manager=None):
        self.config = config
        self.logger = logger
        self.ssl_manager = ssl_manager  # Centralized SSL certificate manager
        self.nginx_config_path = "/etc/nginx/sites-available"
        self.nginx_enabled_path = "/etc/nginx/sites-enabled"

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

            # Domains table - updated schema
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
                    ssl_certificate_id INTEGER, -- Reference to ssl_certificates table
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (ssl_certificate_id) REFERENCES ssl_certificates (id)
                )
            """
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

    def create_subdomain(self, subdomain, parent_domain, app_name, port):
        """Create a new subdomain with nginx configuration and SSL support"""
        try:
            # Validate inputs
            available, message = self.check_subdomain_availability(
                subdomain, parent_domain
            )
            if not available:
                return {"success": False, "error": message}

            full_domain = f"{subdomain}.{parent_domain}"
            self.logger.info(f"Creating subdomain: {full_domain}")

            # Check for existing SSL certificate
            ssl_cert_info = None
            ssl_enabled = False

            if (
                self.ssl_manager
                and self.available_domains[parent_domain]["ssl_enabled"]
            ):
                cert_check = self.ssl_manager.check_certificate_for_domain(full_domain)
                if cert_check["available"]:
                    ssl_cert_info = cert_check["certificate"]
                    ssl_enabled = True
                    self.logger.info(
                        f"Found existing SSL certificate for {full_domain}"
                    )
                else:
                    self.logger.info(
                        f"No SSL certificate found for {full_domain}, creating HTTP-only configuration"
                    )

            # Create nginx configuration
            nginx_config_path = self._create_nginx_config(
                full_domain, port, app_name, ssl_enabled, ssl_cert_info
            )
            if not nginx_config_path:
                return {
                    "success": False,
                    "error": "Failed to create nginx configuration",
                }

            # Enable nginx site
            if not self._enable_nginx_site(full_domain):
                return {"success": False, "error": "Failed to enable nginx site"}

            # Save to database
            conn = self.get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO domains (
                    domain_name, parent_domain, port, app_name, 
                    nginx_config_path, ssl_enabled, ssl_certificate_id, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    full_domain,
                    parent_domain,
                    port,
                    app_name,
                    nginx_config_path,
                    ssl_enabled,
                    ssl_cert_info["id"] if ssl_cert_info else None,
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
                    "ssl_enabled": ssl_enabled,
                    "nginx_config": nginx_config_path,
                    "url": f"http{'s' if ssl_enabled else ''}://{full_domain}",
                }
            else:
                return {"success": False, "error": "Failed to reload nginx"}

        except Exception as e:
            self.logger.error(f"Failed to create subdomain: {e}")
            return {"success": False, "error": str(e)}

    def _create_nginx_config(
        self, domain, port, app_name, ssl_enabled=False, ssl_cert_info=None
    ):
        """Create nginx configuration for subdomain"""
        try:
            config_path = f"{self.nginx_config_path}/{domain}"

            if ssl_enabled and ssl_cert_info:
                # SSL-enabled configuration
                nginx_config = f"""# Nginx configuration for {domain}
# App: {app_name}
# Port: {port}
# SSL: Enabled

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
    ssl_certificate {ssl_cert_info['fullchain_path']};
    ssl_certificate_key {ssl_cert_info['private_key_path']};
    
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
}}"""
            else:
                # HTTP-only configuration
                nginx_config = f"""# Nginx configuration for {domain}
# App: {app_name}
# Port: {port}
# SSL: Disabled

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
}}"""

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

    def enable_ssl_for_domain(self, domain):
        """Enable SSL for an existing domain"""
        try:
            if not self.ssl_manager:
                return {"success": False, "error": "SSL manager not available"}

            domain_info = self.get_domain_info(domain)
            if not domain_info:
                return {"success": False, "error": "Domain not found"}

            if domain_info["ssl_enabled"]:
                return {"success": True, "message": "SSL already enabled"}

            # Check for certificate
            cert_check = self.ssl_manager.check_certificate_for_domain(domain)
            if not cert_check["available"]:
                return {
                    "success": False,
                    "error": "No SSL certificate available for this domain",
                }

            # Recreate nginx config with SSL
            ssl_cert_info = cert_check["certificate"]
            nginx_config_path = self._create_nginx_config(
                domain,
                domain_info["port"],
                domain_info["app_name"],
                True,
                ssl_cert_info,
            )

            if nginx_config_path and self._reload_nginx():
                # Update database
                conn = self.get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE domains 
                    SET ssl_enabled = TRUE, ssl_certificate_id = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE domain_name = ?
                """,
                    (ssl_cert_info["id"], domain),
                )
                conn.commit()
                conn.close()

                return {"success": True, "message": "SSL enabled successfully"}
            else:
                return {
                    "success": False,
                    "error": "Failed to update nginx configuration",
                }

        except Exception as e:
            self.logger.error(f"Failed to enable SSL for {domain}: {e}")
            return {"success": False, "error": str(e)}

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
                SELECT d.*, c.domain as cert_domain, c.expires_at as cert_expires
                FROM domains d
                LEFT JOIN ssl_certificates c ON d.ssl_certificate_id = c.id
                WHERE d.domain_name = ?
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
                    "certificate_domain": result[12],
                    "certificate_expires": result[13],
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

            query = """
                SELECT d.*, c.domain as cert_domain, c.expires_at as cert_expires
                FROM domains d
                LEFT JOIN ssl_certificates c ON d.ssl_certificate_id = c.id
                WHERE 1=1
            """
            params = []

            if parent_domain:
                query += " AND d.parent_domain = ?"
                params.append(parent_domain)

            if status:
                query += " AND d.status = ?"
                params.append(status)

            query += " ORDER BY d.created_at DESC"

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
                        "certificate_domain": row[12],
                        "certificate_expires": row[13],
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

            # Remove domain record
            conn = self.get_db_connection()
            cursor = conn.cursor()
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
        db_path = self.config.get("database_path", "/tmp/hosting/hosting.db")
        return sqlite3.connect(db_path, timeout=30.0)

    # Add to your hosting manager or domain manager to allow root domain deployment

    def determine_deployment_domain(
        self, app_name, preferred_subdomain=None, parent_domain=None
    ):
        """Determine whether to deploy to root domain or subdomain"""
        try:
            # Get all available parent domains from your domain manager
            available_domains = self.get_available_domains()  # Your existing method

            results = []

            for domain_name, domain_config in available_domains.items():
                # Check if root domain is already taken
                root_domain_taken = self.is_domain_active(domain_name)

                deployment_option = {
                    "parent_domain": domain_name,
                    "domain_config": domain_config,
                }

                if not root_domain_taken:
                    # Root domain is available - recommend it as default
                    deployment_option.update(
                        {
                            "recommended_domain": domain_name,
                            "domain_type": "root",
                            "full_domain": domain_name,
                            "is_default": True,
                            "reason": "Root domain available",
                        }
                    )
                else:
                    # Root domain taken - must use subdomain
                    subdomain = preferred_subdomain or app_name.lower()
                    full_domain = f"{subdomain}.{domain_name}"

                    # Check if subdomain is available
                    subdomain_taken = self.is_domain_active(full_domain)

                    if not subdomain_taken:
                        deployment_option.update(
                            {
                                "recommended_domain": full_domain,
                                "domain_type": "subdomain",
                                "subdomain": subdomain,
                                "full_domain": full_domain,
                                "is_default": False,
                                "reason": f"Root domain {domain_name} already in use",
                            }
                        )
                    else:
                        # Both root and preferred subdomain taken
                        deployment_option.update(
                            {
                                "recommended_domain": None,
                                "domain_type": "unavailable",
                                "reason": f"Both {domain_name} and {full_domain} are in use",
                            }
                        )

                results.append(deployment_option)

            return {
                "success": True,
                "options": results,
                "default_option": next(
                    (opt for opt in results if opt.get("is_default")),
                    results[0] if results else None,
                ),
            }

        except Exception as e:
            self.logger.error(f"Failed to determine deployment domain: {e}")
            return {"success": False, "error": str(e), "options": []}

    def is_domain_active(self, domain_name):
        """Check if a domain (root or subdomain) is already active"""
        try:
            conn = self.get_database_connection()
            if not conn:
                return False

            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM domains WHERE domain_name = ? AND status = 'active'",
                (domain_name,),
            )

            count = cursor.fetchone()[0]
            conn.close()

            return count > 0

        except Exception as e:
            self.logger.error(f"Failed to check domain status: {e}")
            return True  # Assume taken to be safe

    def get_domain_suggestions(self, app_name, parent_domain=None):
        """Get domain deployment suggestions for an app"""
        try:
            # If specific parent domain requested, check only that one
            if parent_domain:
                available_domains = {
                    parent_domain: self.get_available_domains().get(parent_domain, {})
                }
            else:
                available_domains = self.get_available_domains()

            suggestions = []

            for domain_name, domain_config in available_domains.items():
                # Option 1: Root domain
                root_available = not self.is_domain_active(domain_name)
                if root_available:
                    suggestions.append(
                        {
                            "domain": domain_name,
                            "type": "root",
                            "available": True,
                            "priority": 1,
                            "description": f"Deploy to root domain {domain_name}",
                        }
                    )

                # Option 2: App name subdomain
                app_subdomain = f"{app_name.lower()}.{domain_name}"
                app_subdomain_available = not self.is_domain_active(app_subdomain)
                if app_subdomain_available:
                    suggestions.append(
                        {
                            "domain": app_subdomain,
                            "type": "subdomain",
                            "subdomain": app_name.lower(),
                            "parent_domain": domain_name,
                            "available": True,
                            "priority": 2 if root_available else 1,
                            "description": f"Deploy to subdomain {app_subdomain}",
                        }
                    )

                # Option 3: Custom subdomain slots
                for i in range(1, 4):  # Suggest up to 3 alternatives
                    alt_subdomain = f"{app_name.lower()}{i}.{domain_name}"
                    if not self.is_domain_active(alt_subdomain):
                        suggestions.append(
                            {
                                "domain": alt_subdomain,
                                "type": "subdomain",
                                "subdomain": f"{app_name.lower()}{i}",
                                "parent_domain": domain_name,
                                "available": True,
                                "priority": 3,
                                "description": f"Deploy to alternative subdomain {alt_subdomain}",
                            }
                        )
                        break  # Only suggest one alternative per domain

            # Sort by priority (1 = highest priority)
            suggestions.sort(key=lambda x: x["priority"])

            return {
                "success": True,
                "suggestions": suggestions,
                "default_suggestion": suggestions[0] if suggestions else None,
            }

        except Exception as e:
            self.logger.error(f"Failed to get domain suggestions: {e}")
            return {"success": False, "error": str(e), "suggestions": []}

    # Add these methods to your domain manager

    def create_root_domain(self, domain_name, app_name, port):
        """Create a root domain deployment (e.g., example.com)"""
        try:
            self.logger.info(f"Creating root domain deployment: {domain_name}")

            # Check if domain is already in use
            if self.is_domain_active(domain_name):
                return {
                    "success": False,
                    "error": f"Root domain {domain_name} is already in use",
                }

            # Create the domain using hosting manager
            success = self.hosting_manager.deploy_domain(
                domain_name=domain_name, port=port, site_type="node", app_name=app_name
            )

            if not success:
                return {
                    "success": False,
                    "error": f"Failed to create domain configuration for {domain_name}",
                }

            # Create nginx configuration for root domain
            self._create_nginx_root_domain_config(domain_name, port)

            # Check for SSL availability
            ssl_enabled = self._setup_ssl_if_available(domain_name)

            self.logger.info(f"Root domain {domain_name} created successfully")

            return {
                "success": True,
                "domain_type": "root",
                "full_domain": domain_name,
                "port": port,
                "ssl_enabled": ssl_enabled,
                "app_name": app_name,
            }

        except Exception as e:
            self.logger.error(f"Failed to create root domain {domain_name}: {e}")
            return {"success": False, "error": str(e)}

    def create_subdomain(self, subdomain, parent_domain, app_name, port):
        """Create a subdomain deployment (e.g., app.example.com)"""
        try:
            full_domain = f"{subdomain}.{parent_domain}"
            self.logger.info(f"Creating subdomain deployment: {full_domain}")

            # Check if subdomain is already in use
            if self.is_domain_active(full_domain):
                return {
                    "success": False,
                    "error": f"Subdomain {full_domain} is already in use",
                }

            # Create the domain using hosting manager
            success = self.hosting_manager.deploy_domain(
                domain_name=full_domain, port=port, site_type="node", app_name=app_name
            )

            if not success:
                return {
                    "success": False,
                    "error": f"Failed to create domain configuration for {full_domain}",
                }

            # Create nginx configuration for subdomain
            self._create_nginx_subdomain_config(full_domain, port)

            # Check for SSL availability
            ssl_enabled = self._setup_ssl_if_available(full_domain)

            self.logger.info(f"Subdomain {full_domain} created successfully")

            return {
                "success": True,
                "domain_type": "subdomain",
                "subdomain": subdomain,
                "parent_domain": parent_domain,
                "full_domain": full_domain,
                "port": port,
                "ssl_enabled": ssl_enabled,
                "app_name": app_name,
            }

        except Exception as e:
            self.logger.error(f"Failed to create subdomain {full_domain}: {e}")
            return {"success": False, "error": str(e)}

    def _create_nginx_root_domain_config(self, domain_name, port):
        """Create nginx configuration for root domain"""
        try:
            nginx_config = f"""server {{
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
            proxy_cache_bypass $http_upgrade;
            
            # Root domain specific headers
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Server $host;
            
            # Timeout settings
            proxy_connect_timeout       60s;
            proxy_send_timeout          60s;
            proxy_read_timeout          60s;
        }}
        
        # Handle static assets with caching
        location ~* \\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {{
            proxy_pass http://localhost:{port};
            expires 1y;
            add_header Cache-Control "public, immutable";
        }}
        
        # Handle API routes
        location /api/ {{
            proxy_pass http://localhost:{port};
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }}
    }}"""

            config_path = f"/etc/nginx/sites-available/{domain_name}"
            enabled_path = f"/etc/nginx/sites-enabled/{domain_name}"

            # Write config
            with open(config_path, "w") as f:
                f.write(nginx_config)

            self.logger.info(f"Created nginx config: {config_path}")

            # Enable site
            if os.path.exists(enabled_path):
                os.remove(enabled_path)
            os.symlink(config_path, enabled_path)

            self.logger.info(f"Enabled nginx site: {domain_name}")

            # Test and reload nginx
            if self._test_nginx_config():
                subprocess.run(["systemctl", "reload", "nginx"], capture_output=True)
                self.logger.info(f"Nginx reloaded for {domain_name}")
            else:
                self.logger.error("Nginx config test failed")

        except Exception as e:
            self.logger.error(f"Failed to create nginx config for root domain: {e}")

    def _create_nginx_subdomain_config(self, full_domain, port):
        """Create nginx configuration for subdomain"""
        try:
            nginx_config = f"""server {{
        listen 80;
        server_name {full_domain};
        
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
            
            # Subdomain specific headers
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Server $host;
            
            # Timeout settings
            proxy_connect_timeout       60s;
            proxy_send_timeout          60s;
            proxy_read_timeout          60s;
        }}
        
        # Handle static assets with caching
        location /_next/static/ {{
            proxy_pass http://localhost:{port};
            proxy_cache_valid 200 60m;
            expires 1y;
            add_header Cache-Control "public, immutable";
        }}
    }}"""

            config_path = f"/etc/nginx/sites-available/{full_domain}"
            enabled_path = f"/etc/nginx/sites-enabled/{full_domain}"

            # Write config
            with open(config_path, "w") as f:
                f.write(nginx_config)

            self.logger.info(f"Created nginx config: {config_path}")

            # Enable site
            if os.path.exists(enabled_path):
                os.remove(enabled_path)
            os.symlink(config_path, enabled_path)

            self.logger.info(f"Enabled nginx site: {full_domain}")

            # Test and reload nginx
            if self._test_nginx_config():
                subprocess.run(["systemctl", "reload", "nginx"], capture_output=True)
            else:
                self.logger.error("Nginx config test failed")

        except Exception as e:
            self.logger.error(f"Failed to create nginx config for subdomain: {e}")

    def _setup_ssl_if_available(self, domain_name):
        """Setup SSL certificate if possible"""
        try:
            # Check if SSL is already configured
            ssl_config_exists = os.path.exists(
                f"/etc/nginx/sites-available/{domain_name}-ssl"
            )

            if ssl_config_exists:
                self.logger.info(f"SSL already configured for {domain_name}")
                return True

            # Try to obtain SSL certificate with certbot
            result = subprocess.run(
                [
                    "certbot",
                    "--nginx",
                    "-d",
                    domain_name,
                    "--non-interactive",
                    "--agree-tos",
                    "--email",
                    "admin@" + domain_name.split(".")[-2:],  # Use domain for email
                    "--redirect",
                ],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                self.logger.info(f"SSL certificate obtained for {domain_name}")
                return True
            else:
                self.logger.info(f"SSL setup failed for {domain_name}: {result.stderr}")
                return False

        except Exception as e:
            self.logger.warning(f"SSL setup error for {domain_name}: {e}")
            return False

    def _test_nginx_config(self):
        """Test nginx configuration"""
        try:
            result = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def get_deployment_status(self, domain_name):
        """Get status of a domain deployment"""
        try:
            conn = self.hosting_manager.get_database_connection()
            if not conn:
                return {"status": "unknown", "error": "Database connection failed"}

            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT d.domain_name, d.port, d.app_name, d.status, d.site_type,
                    p.status as process_status, p.pid
                FROM domains d
                LEFT JOIN processes p ON d.app_name = p.name
                WHERE d.domain_name = ?
            """,
                (domain_name,),
            )

            result = cursor.fetchone()
            conn.close()

            if not result:
                return {"status": "not_found"}

            return {
                "status": "active" if result[3] == "active" else "inactive",
                "domain_name": result[0],
                "port": result[1],
                "app_name": result[2],
                "site_type": result[4],
                "process_status": result[5] or "unknown",
                "process_pid": result[6],
            }

        except Exception as e:
            self.logger.error(f"Failed to get deployment status: {e}")
            return {"status": "error", "error": str(e)}
