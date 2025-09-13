# src/hosting/first_run_setup.py
"""
Automated SSL and system setup for first deployment
Handles initial server configuration and SSL certificate setup
"""

import os
import sys
import json
import subprocess
import sqlite3
import logging
import time
from pathlib import Path
from datetime import datetime


class FirstRunSetup:
    """Handles first-run setup for new server deployments"""

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.setup_marker_file = "/tmp/hosting/.first_run_complete"
        self.ssl_cert_path = "/etc/letsencrypt/live"

    def is_first_run(self):
        """Check if this is the first run on this server"""
        return not os.path.exists(self.setup_marker_file)

    def mark_setup_complete(self):
        """Mark first-run setup as complete"""
        os.makedirs(os.path.dirname(self.setup_marker_file), exist_ok=True)
        with open(self.setup_marker_file, "w") as f:
            f.write(
                json.dumps(
                    {
                        "setup_completed_at": datetime.now().isoformat(),
                        "version": "1.0",
                        "ssl_method": getattr(self, "_ssl_method", "auto"),
                    }
                )
            )

    def run_first_time_setup(self):
        """Run complete first-time setup"""
        try:
            self.logger.info("🚀 Starting first-run server setup...")

            # 1. Install system dependencies
            if not self._install_dependencies():
                return False

            # 2. Setup directory structure
            if not self._setup_directories():
                return False

            # 3. Initialize database
            if not self._initialize_database():
                return False

            # 4. Setup SSL certificates
            ssl_result = self._setup_ssl_certificates()
            if ssl_result["success"]:
                self.logger.info("✅ SSL certificates configured successfully")
            else:
                self.logger.warning(f"⚠️ SSL setup incomplete: {ssl_result['message']}")
                self.logger.info("🔄 Server will operate in HTTP-only mode")

            # 5. Configure nginx
            if not self._setup_nginx():
                return False

            # 6. Setup automatic renewal
            if not self._setup_auto_renewal():
                return False

            # 7. Mark setup complete
            self.mark_setup_complete()

            self.logger.info("🎉 First-run setup completed successfully!")
            return True

        except Exception as e:
            self.logger.error(f"❌ First-run setup failed: {e}")
            return False

    def _install_dependencies(self):
        """Install required system dependencies"""
        try:
            self.logger.info("📦 Installing system dependencies...")

            # Update package list
            result = subprocess.run(["apt", "update"], capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error(f"Failed to update package list: {result.stderr}")
                return False

            # Install required packages
            packages = [
                "certbot",
                "python3-certbot-nginx",
                "openssl",
                "nginx",
                "python3-pip",
                "sqlite3",
                "curl",
                "systemd",
            ]

            for package in packages:
                self.logger.info(f"Installing {package}...")
                result = subprocess.run(
                    ["apt", "install", "-y", package], capture_output=True, text=True
                )
                if result.returncode != 0:
                    self.logger.warning(f"Failed to install {package}: {result.stderr}")

            return True

        except Exception as e:
            self.logger.error(f"Dependency installation failed: {e}")
            return False

    def _setup_directories(self):
        """Setup required directory structure"""
        try:
            self.logger.info("📁 Setting up directory structure...")

            directories = [
                "/tmp/hosting",
                "/tmp/www/domains",
                "/var/log/hosting",
                "/etc/nginx/sites-available",
                "/etc/nginx/sites-enabled",
            ]

            for directory in directories:
                os.makedirs(directory, exist_ok=True)
                self.logger.info(f"Created directory: {directory}")

            return True

        except Exception as e:
            self.logger.error(f"Directory setup failed: {e}")
            return False

    def _initialize_database(self):
        """Initialize hosting database"""
        try:
            self.logger.info("🗄️ Initializing hosting database...")

            # Import SSL and Domain managers
            from .ssl_manager import SSLCertificateManager
            from .domain_manager import DomainManager

            # Initialize managers
            ssl_manager = SSLCertificateManager(self.config, self.logger)
            domain_manager = DomainManager(self.config, self.logger, ssl_manager)

            # Setup database
            db_path = self.config.get("database_path", "/tmp/hosting/hosting.db")
            conn = sqlite3.connect(db_path)

            ssl_manager.setup_database(conn)
            domain_manager.setup_database(conn)

            conn.close()

            self.logger.info("✅ Database initialized successfully")
            return True

        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
            return False

    def _setup_ssl_certificates(self):
        """Setup SSL certificates with multiple fallback methods"""
        try:
            self.logger.info("🔐 Setting up SSL certificates...")

            domains = self.config.get(
                "domains",
                {
                    "smartwave.co.za": {"email": "admin@smartwave.co.za"},
                    "datablox.co.za": {"email": "admin@datablox.co.za"},
                    "mondaycafe.co.za": {"email": "admin@mondaycafe.co.za"},
                },
            )

            successful_certs = 0
            total_domains = len(domains)

            for domain, domain_config in domains.items():
                result = self._setup_single_domain_ssl(domain, domain_config)
                if result["success"]:
                    successful_certs += 1
                    self.logger.info(f"✅ SSL configured for {domain}")
                else:
                    self.logger.warning(f"⚠️ SSL failed for {domain}: {result['error']}")

            # Import certificates into database
            if successful_certs > 0:
                self._import_certificates_to_database()

            if successful_certs == total_domains:
                self._ssl_method = "full_auto"
                return {
                    "success": True,
                    "message": f"All {successful_certs} certificates configured",
                }
            elif successful_certs > 0:
                self._ssl_method = "partial_auto"
                return {
                    "success": True,
                    "message": f"{successful_certs}/{total_domains} certificates configured",
                }
            else:
                self._ssl_method = "manual_required"
                return {
                    "success": False,
                    "message": "No certificates could be configured automatically",
                }

        except Exception as e:
            self.logger.error(f"SSL setup failed: {e}")
            return {"success": False, "message": str(e)}

    def _setup_single_domain_ssl(self, domain, domain_config):
        """Setup SSL for a single domain with multiple methods"""

        # Method 1: Try HTTP challenge first (works if domain points to this server)
        self.logger.info(f"Trying HTTP challenge for {domain}...")
        result = self._try_http_challenge(domain, domain_config)
        if result["success"]:
            return result

        # Method 2: Try standalone method
        self.logger.info(f"Trying standalone method for {domain}...")
        result = self._try_standalone_method(domain, domain_config)
        if result["success"]:
            return result

        # Method 3: Generate self-signed certificate for development
        self.logger.info(f"Generating self-signed certificate for {domain}...")
        return self._generate_self_signed_cert(domain)

    def _try_http_challenge(self, domain, domain_config):
        """Try HTTP challenge method"""
        try:
            email = domain_config.get("email", "admin@localhost")

            cmd = [
                "certbot",
                "certonly",
                "--nginx",
                "--non-interactive",
                "--agree-tos",
                "--email",
                email,
                "--cert-name",
                domain,
                "-d",
                domain,
                "-d",
                f"*.{domain}",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                return {"success": True, "method": "http_challenge"}
            else:
                return {"success": False, "error": result.stderr}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _try_standalone_method(self, domain, domain_config):
        """Try standalone method (requires port 80/443 to be free)"""
        try:
            email = domain_config.get("email", "admin@localhost")

            # Stop nginx temporarily
            subprocess.run(["systemctl", "stop", "nginx"], capture_output=True)

            cmd = [
                "certbot",
                "certonly",
                "--standalone",
                "--non-interactive",
                "--agree-tos",
                "--email",
                email,
                "--cert-name",
                domain,
                "-d",
                domain,
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # Restart nginx
            subprocess.run(["systemctl", "start", "nginx"], capture_output=True)

            if result.returncode == 0:
                return {"success": True, "method": "standalone"}
            else:
                return {"success": False, "error": result.stderr}

        except Exception as e:
            # Make sure nginx is restarted
            subprocess.run(["systemctl", "start", "nginx"], capture_output=True)
            return {"success": False, "error": str(e)}

    def _generate_self_signed_cert(self, domain):
        """Generate self-signed certificate for development"""
        try:
            cert_dir = f"/etc/ssl/self-signed/{domain}"
            os.makedirs(cert_dir, exist_ok=True)

            # Generate private key
            subprocess.run(
                ["openssl", "genrsa", "-out", f"{cert_dir}/privkey.pem", "2048"],
                capture_output=True,
                check=True,
            )

            # Generate certificate
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-new",
                    "-x509",
                    "-key",
                    f"{cert_dir}/privkey.pem",
                    "-out",
                    f"{cert_dir}/fullchain.pem",
                    "-days",
                    "365",
                    "-subj",
                    f"/CN={domain}/O=Self-Signed/C=US",
                ],
                capture_output=True,
                check=True,
            )

            # Copy for compatibility
            subprocess.run(["cp", f"{cert_dir}/fullchain.pem", f"{cert_dir}/cert.pem"])

            return {"success": True, "method": "self_signed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _import_certificates_to_database(self):
        """Import existing certificates into database"""
        try:
            from .ssl_manager import SSLCertificateManager

            ssl_manager = SSLCertificateManager(self.config, self.logger)

            # Check both letsencrypt and self-signed locations
            cert_locations = ["/etc/letsencrypt/live", "/etc/ssl/self-signed"]

            for cert_location in cert_locations:
                if not os.path.exists(cert_location):
                    continue

                for domain_dir in os.listdir(cert_location):
                    domain_path = f"{cert_location}/{domain_dir}"
                    if os.path.isdir(domain_path):
                        cert_paths = {
                            "cert_path": f"{domain_path}/cert.pem",
                            "privkey_path": f"{domain_path}/privkey.pem",
                            "fullchain_path": f"{domain_path}/fullchain.pem",
                        }

                        # Check if all required files exist
                        if all(os.path.exists(path) for path in cert_paths.values()):
                            cert_type = (
                                "self_signed"
                                if "self-signed" in cert_location
                                else "single"
                            )
                            cert_id = ssl_manager._store_certificate_info(
                                domain_dir, cert_type, [domain_dir], cert_paths
                            )
                            if cert_id:
                                self.logger.info(
                                    f"Imported certificate for {domain_dir}"
                                )

        except Exception as e:
            self.logger.error(f"Failed to import certificates: {e}")

    def _setup_nginx(self):
        """Setup nginx base configuration"""
        try:
            self.logger.info("🌐 Setting up nginx...")

            # Enable nginx
            subprocess.run(["systemctl", "enable", "nginx"], capture_output=True)
            subprocess.run(["systemctl", "start", "nginx"], capture_output=True)

            # Test configuration
            result = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error(f"Nginx configuration test failed: {result.stderr}")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Nginx setup failed: {e}")
            return False

    def _setup_auto_renewal(self):
        """Setup automatic certificate renewal"""
        try:
            self.logger.info("🔄 Setting up automatic certificate renewal...")

            # Create renewal script
            renewal_script = """#!/bin/bash
# Auto-renewal script for SSL certificates
/usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx'
"""

            script_path = "/etc/cron.daily/certbot-renewal"
            with open(script_path, "w") as f:
                f.write(renewal_script)

            os.chmod(script_path, 0o755)

            # Also add to crontab as backup
            cron_entry = "0 3 * * * /usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx'"

            # Get current crontab
            result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            current_cron = result.stdout if result.returncode == 0 else ""

            if cron_entry not in current_cron:
                new_cron = current_cron + f"\n{cron_entry}\n"
                subprocess.run(["crontab", "-"], input=new_cron, text=True)

            return True

        except Exception as e:
            self.logger.error(f"Auto-renewal setup failed: {e}")
            return False


# Integration with hosting manager
class HostingManagerWithSetup:
    """Hosting manager that handles first-run setup"""

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.first_run_setup = FirstRunSetup(config, logger)
        self.ssl_manager = None
        self.domain_manager = None

    def initialize(self):
        """Initialize hosting manager with first-run setup"""
        try:
            # Check if first-run setup is needed
            if self.first_run_setup.is_first_run():
                self.logger.info("🚀 First deployment detected - running setup...")

                if not self.first_run_setup.run_first_time_setup():
                    self.logger.error("❌ First-run setup failed")
                    return False

                self.logger.info("✅ First-run setup completed successfully")

            # Initialize SSL and domain managers
            from .ssl_manager import SSLCertificateManager
            from .domain_manager import DomainManager

            self.ssl_manager = SSLCertificateManager(self.config, self.logger)
            self.domain_manager = DomainManager(
                self.config, self.logger, self.ssl_manager
            )

            return True

        except Exception as e:
            self.logger.error(f"Hosting manager initialization failed: {e}")
            return False

    def get_managers(self):
        """Get initialized managers"""
        return {"ssl_manager": self.ssl_manager, "domain_manager": self.domain_manager}


# Example usage in your main app.py
"""
# Replace your current initialization with:

from src.hosting.first_run_setup import HostingManagerWithSetup

# Initialize with first-run setup
hosting_setup = HostingManagerWithSetup(config, logger)

if not hosting_setup.initialize():
    logger.error("Failed to initialize hosting manager")
    sys.exit(1)

# Get managers
managers = hosting_setup.get_managers()
ssl_manager = managers['ssl_manager']
domain_manager = managers['domain_manager']

# Pass to your API
api = HostingAPI(
    hosting_manager=hosting_manager,
    process_monitor=process_monitor,
    health_checker=health_checker,
    domain_manager=domain_manager,
    config=config,
    logger=logger
)

# Add SSL manager to dependencies  
api.deps["ssl_manager"] = ssl_manager
"""
