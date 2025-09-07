# ssl_setup.py - Initialize SSL certificates in database after manual setup
"""
Run this script after manually creating SSL certificates to import them into the database
"""

import sys
import os

sys.path.append("./hosting-manager")  # Update this path

from src.hosting.ssl_manager import SSLCertificateManager
from src.hosting.domain_manager import DomainManager
import sqlite3
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def setup_ssl_certificates():
    """Initialize SSL certificates in the database"""

    # Configuration
    config = {
        "database_path": "/tmp/hosting/hosting.db",
        "ssl_email": "admin@smartwave.co.za",
    }

    # Initialize SSL manager
    ssl_manager = SSLCertificateManager(config, logger)

    # Setup database
    conn = sqlite3.connect(config["database_path"])
    ssl_manager.setup_database(conn)

    # List of domains to import
    domains_to_import = [
        {
            "domain": "smartwave.co.za",
            "type": "wildcard",
            "extra_domains": ["*.smartwave.co.za"],
        },
        {
            "domain": "datablox.co.za",
            "type": "wildcard",
            "extra_domains": ["*.datablox.co.za"],
        },
        {
            "domain": "mondaycafe.co.za",
            "type": "wildcard",
            "extra_domains": ["*.mondaycafe.co.za"],
        },
    ]

    # Import existing certificates
    for domain_info in domains_to_import:
        domain = domain_info["domain"]
        cert_type = domain_info["type"]

        # Check if certificate files exist
        cert_path = f"/etc/letsencrypt/live/{domain}"
        if os.path.exists(cert_path):
            logger.info(f"Importing certificate for {domain}")

            # Create certificate record in database
            cert_paths = {
                "cert_path": f"{cert_path}/cert.pem",
                "privkey_path": f"{cert_path}/privkey.pem",
                "fullchain_path": f"{cert_path}/fullchain.pem",
                "chain_path": f"{cert_path}/chain.pem",
            }

            cert_id = ssl_manager._store_certificate_info(
                domain,
                cert_type,
                [domain] + domain_info.get("extra_domains", []),
                cert_paths,
            )

            if cert_id:
                logger.info(f"Successfully imported certificate {cert_id} for {domain}")
            else:
                logger.error(f"Failed to import certificate for {domain}")
        else:
            logger.warning(f"Certificate not found for {domain} at {cert_path}")

    conn.close()
    logger.info("SSL certificate initialization complete")


# Updated hosting manager initialization
def create_hosting_manager_with_ssl():
    """Create hosting manager with SSL support"""

    config = {
        "database_path": "/tmp/hosting/hosting.db",
        "ssl_email": "admin@smartwave.co.za",
    }

    logger = logging.getLogger(__name__)

    # Initialize SSL manager
    ssl_manager = SSLCertificateManager(config, logger)

    # Initialize domain manager with SSL support
    domain_manager = DomainManager(config, logger, ssl_manager)

    # Setup databases
    conn = sqlite3.connect(config["database_path"])
    ssl_manager.setup_database(conn)
    domain_manager.setup_database(conn)
    conn.close()

    return ssl_manager, domain_manager


# Test SSL functionality
def test_ssl_certificates():
    """Test SSL certificate functionality"""

    ssl_manager, domain_manager = create_hosting_manager_with_ssl()

    # Test domains
    test_domains = [
        "test.smartwave.co.za",
        "api.datablox.co.za",
        "app.mondaycafe.co.za",
    ]

    for domain in test_domains:
        cert_check = ssl_manager.check_certificate_for_domain(domain)
        if cert_check["available"]:
            logger.info(f"✅ SSL certificate available for {domain}")
            logger.info(f"   Certificate: {cert_check['certificate']['domain']}")
            logger.info(f"   Type: {cert_check['certificate']['certificate_type']}")
            logger.info(f"   Expires: {cert_check['certificate']['expires_at']}")
        else:
            logger.warning(f"❌ No SSL certificate available for {domain}")


if __name__ == "__main__":
    print("Setting up SSL certificates...")
    setup_ssl_certificates()

    print("\nTesting SSL functionality...")
    test_ssl_certificates()

    print("\nSSL setup complete!")
    print("You can now update your hosting manager to use SSL support.")


# Example updated app.py integration
"""
# In your main hosting manager startup code (app.py or similar):

from src.hosting.ssl_manager import SSLCertificateManager
from src.hosting.domain_manager import DomainManager

# Initialize with SSL support
ssl_manager = SSLCertificateManager(config, logger)
domain_manager = DomainManager(config, logger, ssl_manager)

# Pass SSL-enabled domain manager to your API
api = HostingAPI(
    hosting_manager=hosting_manager,
    process_monitor=process_monitor, 
    health_checker=health_checker,
    domain_manager=domain_manager,  # Now SSL-enabled
    config=config,
    logger=logger
)
"""


# SSL Management Commands (add these to your hosting manager)
class SSLCommands:
    """SSL management commands for hosting manager"""

    def __init__(self, ssl_manager):
        self.ssl_manager = ssl_manager

    def list_certificates(self):
        """List all SSL certificates"""
        return self.ssl_manager.list_certificates()

    def check_certificate(self, domain):
        """Check certificate for specific domain"""
        return self.ssl_manager.check_certificate_for_domain(domain)

    def renew_certificate(self, domain, force=False):
        """Renew SSL certificate"""
        return self.ssl_manager.renew_certificate(domain, force)

    def install_certificate(self, domain, cert_type="single"):
        """Install new SSL certificate"""
        return self.ssl_manager.install_certificate(domain, cert_type)

    def auto_renew_all(self):
        """Auto-renew expiring certificates"""
        return self.ssl_manager.auto_renew_certificates()


# API endpoints for SSL management (add to your app.py)
"""
@self.app.route("/api/ssl/certificates", methods=["GET"])
def list_ssl_certificates():
    try:
        if 'ssl_manager' not in self.deps:
            return {"success": False, "error": "SSL manager not available"}, 503
            
        certificates = self.deps['ssl_manager'].list_certificates()
        return {
            "success": True,
            "certificates": certificates,
            "count": len(certificates)
        }
    except Exception as e:
        if self.deps.get("logger"):
            self.deps["logger"].error(f"SSL certificates list error: {e}")
        return {"success": False, "error": str(e)}, 500

@self.app.route("/api/ssl/check/<domain>", methods=["GET"])  
def check_ssl_certificate(domain):
    try:
        if 'ssl_manager' not in self.deps:
            return {"success": False, "error": "SSL manager not available"}, 503
            
        cert_check = self.deps['ssl_manager'].check_certificate_for_domain(domain)
        return {
            "success": True,
            "domain": domain,
            "certificate_available": cert_check['available'],
            "certificate": cert_check.get('certificate')
        }
    except Exception as e:
        if self.deps.get("logger"):
            self.deps["logger"].error(f"SSL certificate check error: {e}")
        return {"success": False, "error": str(e)}, 500

@self.app.route("/api/ssl/renew/<domain>", methods=["POST"])
def renew_ssl_certificate(domain):
    try:
        if 'ssl_manager' not in self.deps:
            return {"success": False, "error": "SSL manager not available"}, 503
            
        data = request.get_json() or {}
        force = data.get('force', False)
        
        result = self.deps['ssl_manager'].renew_certificate(domain, force)
        return result
    except Exception as e:
        if self.deps.get("logger"):
            self.deps["logger"].error(f"SSL certificate renewal error: {e}")
        return {"success": False, "error": str(e)}, 500
"""
