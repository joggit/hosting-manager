"""
Simple SSL Certificate Manager using Let's Encrypt
"""

import subprocess
import os
from datetime import datetime


class SSLManager:
    """Simple SSL manager for Let's Encrypt certificates"""

    def __init__(self, logger, config=None):
        self.logger = logger
        self.config = config or {}
        self.certbot_path = self._find_certbot()

    def _find_certbot(self):
        """Find certbot executable"""
        paths = ["/usr/bin/certbot", "/snap/bin/certbot", "/usr/local/bin/certbot"]
        for path in paths:
            if os.path.exists(path):
                self.logger.info(f"✓ Found certbot at {path}")
                return path
        self.logger.error("❌ Certbot not found")
        return None

    def setup_certificate(self, domain_name, email):
        """
        Setup SSL certificate for domain

        Returns: (success: bool, message: str, cert_info: dict)
        """
        if not self.certbot_path:
            return (
                False,
                "Certbot not installed. Run: sudo apt install certbot python3-certbot-nginx",
                None,
            )

        try:
            self.logger.info(f"🔒 Setting up SSL for {domain_name}")

            # Run certbot
            cmd = [
                self.certbot_path,
                "--nginx",
                "-d",
                domain_name,
                "--non-interactive",
                "--agree-tos",
                "--email",
                email,
                "--redirect",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                cert_info = {
                    "domain": domain_name,
                    "email": email,
                    "cert_path": f"/etc/letsencrypt/live/{domain_name}/fullchain.pem",
                    "installed_at": datetime.now().isoformat(),
                }
                self.logger.info(f"✅ SSL certificate installed for {domain_name}")
                return True, "SSL certificate installed successfully", cert_info
            else:
                error = result.stderr or result.stdout
                self.logger.error(f"❌ SSL setup failed: {error}")
                return False, f"SSL setup failed: {error}", None

        except subprocess.TimeoutExpired:
            return (
                False,
                "SSL setup timed out (300s). Check domain DNS and accessibility.",
                None,
            )
        except Exception as e:
            self.logger.error(f"❌ SSL exception: {e}")
            return False, str(e), None

    def get_certificate_status(self, domain_name):
        """Get SSL certificate status"""
        cert_path = f"/etc/letsencrypt/live/{domain_name}/fullchain.pem"

        if not os.path.exists(cert_path):
            return False, {"ssl_enabled": False, "message": "No certificate found"}

        try:
            # Get expiry date
            result = subprocess.run(
                ["openssl", "x509", "-enddate", "-noout", "-in", cert_path],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                expiry_str = result.stdout.strip().replace("notAfter=", "")
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_date - datetime.now()).days

                return True, {
                    "ssl_enabled": True,
                    "expires": expiry_date.isoformat(),
                    "days_until_expiry": days_left,
                    "certificate_valid": days_left > 0,
                }
        except Exception as e:
            self.logger.warning(f"Could not parse cert details: {e}")

        return True, {"ssl_enabled": True, "message": "Certificate exists"}


def create_ssl_manager(logger, config=None):
    """Factory function to create SSL manager"""
    return SSLManager(logger, config)
