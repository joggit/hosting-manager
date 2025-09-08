#!/usr/bin/env python3
"""
Complete Fixed SSL Setup Script for Hosting Manager v3.0
Handles apt frontend issues and provides robust SSL certificate management
"""

import os
import sys
import sqlite3
import subprocess
import json
import argparse
from datetime import datetime, timedelta
from pathlib import Path


class SSLSetupManager:
    """Complete SSL setup and management system with error handling"""

    def __init__(self):
        self.database_path = "/tmp/hosting/hosting.db"
        self.ssl_email = "admin@smartwave.co.za"
        self.letsencrypt_dir = "/etc/letsencrypt/live"

        # Ensure directories exist
        self.ensure_directories()

    def ensure_directories(self):
        """Create necessary directories"""
        directories = [
            "/tmp/hosting",
            "/tmp/hosting/logs",
            "/tmp/www/domains",
            "/tmp/monitoring",
            "/tmp/process-logs",
            "/tmp/pm2-home",
            "/tmp/npm-cache",
            "/tmp/deployments",
        ]

        for directory in directories:
            try:
                os.makedirs(directory, mode=0o755, exist_ok=True)
                print(f"✅ Created/verified: {directory}")
            except Exception as e:
                print(f"⚠️  Could not create {directory}: {e}")

    def fix_apt_environment(self):
        """Fix apt frontend issues"""
        try:
            # Set environment variables to fix apt frontend issues
            os.environ["DEBIAN_FRONTEND"] = "noninteractive"
            os.environ["DEBCONF_NONINTERACTIVE_SEEN"] = "true"

            print("✅ Fixed apt environment variables")
            return True
        except Exception as e:
            print(f"⚠️  Could not set environment variables: {e}")
            return False

    def install_system_packages(self):
        """Install system packages with proper error handling"""
        try:
            print("📦 Installing system packages...")

            # Fix apt frontend first
            self.fix_apt_environment()

            # Update package list
            print("   Updating package list...")
            result = subprocess.run(
                ["apt-get", "update", "-qq"],
                capture_output=True,
                text=True,
                env=os.environ,
            )

            if result.returncode != 0:
                print(f"⚠️  Package list update had issues: {result.stderr}")

            # List of essential packages
            packages = ["sqlite3", "python3-pip", "nginx", "openssl", "curl", "git"]

            # Install packages individually to handle failures gracefully
            for package in packages:
                print(f"   Installing {package}...")
                result = subprocess.run(
                    ["apt-get", "install", "-y", "-qq", package],
                    capture_output=True,
                    text=True,
                    env=os.environ,
                )

                if result.returncode == 0:
                    print(f"   ✅ {package} installed successfully")
                else:
                    print(
                        f"   ⚠️  {package} installation failed: {result.stderr.strip()}"
                    )

            # Try to install certbot (might fail on some systems)
            print("   Installing certbot...")
            result = subprocess.run(
                ["apt-get", "install", "-y", "-qq", "certbot", "python3-certbot-nginx"],
                capture_output=True,
                text=True,
                env=os.environ,
            )

            if result.returncode == 0:
                print("   ✅ Certbot installed successfully")
            else:
                print("   ⚠️  Certbot installation failed, SSL renewal will be limited")

            return True

        except Exception as e:
            print(f"⚠️  Package installation error: {e}")
            return False

    def install_python_packages(self):
        """Install required Python packages"""
        try:
            print("🐍 Installing Python packages...")

            packages = [
                "flask>=2.3.0",
                "flask-cors>=4.0.0",
                "gunicorn>=20.1.0",
                "psutil>=5.9.0",
                "requests>=2.31.0",
            ]

            for package in packages:
                print(f"   Installing {package}...")
                result = subprocess.run(
                    ["pip3", "install", package, "--quiet"],
                    capture_output=True,
                    text=True,
                )

                if result.returncode == 0:
                    print(f"   ✅ {package} installed")
                else:
                    print(f"   ⚠️  {package} installation failed")

            return True

        except Exception as e:
            print(f"⚠️  Python package installation error: {e}")
            return False

    def setup_database(self):
        """Setup complete database with all required tables"""
        try:
            print("🗄️  Setting up database...")

            # Ensure database directory exists
            os.makedirs(os.path.dirname(self.database_path), mode=0o755, exist_ok=True)

            conn = sqlite3.connect(self.database_path, timeout=30.0)
            cursor = conn.cursor()

            # Enable optimizations
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA temp_store=MEMORY")
            cursor.execute("PRAGMA cache_size=10000")
            cursor.execute("PRAGMA foreign_keys=ON")

            # Create all required tables
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
                
                CREATE TABLE IF NOT EXISTS ssl_certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    certificate_type TEXT DEFAULT 'single',
                    status TEXT DEFAULT 'active',
                    cert_path TEXT,
                    privkey_path TEXT,
                    fullchain_path TEXT,
                    chain_path TEXT,
                    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    auto_renew BOOLEAN DEFAULT 1,
                    domains_covered TEXT,
                    last_renewal_attempt TIMESTAMP,
                    renewal_status TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS ssl_renewal_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    certificate_id INTEGER,
                    domain TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (certificate_id) REFERENCES ssl_certificates (id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_domains_name ON domains(domain_name);
                CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status);
                CREATE INDEX IF NOT EXISTS idx_processes_name ON processes(name);
                CREATE INDEX IF NOT EXISTS idx_processes_status ON processes(status);
                CREATE INDEX IF NOT EXISTS idx_logs_domain ON deployment_logs(domain_name);
                CREATE INDEX IF NOT EXISTS idx_health_domain ON health_checks(domain_name);
                CREATE INDEX IF NOT EXISTS idx_ssl_domain ON ssl_certificates(domain);
                CREATE INDEX IF NOT EXISTS idx_ssl_status ON ssl_certificates(status);
                CREATE INDEX IF NOT EXISTS idx_ssl_expires ON ssl_certificates(expires_at);
                CREATE INDEX IF NOT EXISTS idx_ssl_type ON ssl_certificates(certificate_type);
            """
            )

            conn.commit()
            conn.close()

            print("✅ Database setup completed successfully")
            return True

        except Exception as e:
            print(f"❌ Database setup failed: {e}")
            return False

    def get_certificate_info(self, cert_file):
        """Extract certificate information using openssl"""
        try:
            # Get expiration date
            result = subprocess.run(
                ["openssl", "x509", "-in", cert_file, "-noout", "-enddate"],
                capture_output=True,
                text=True,
            )

            expires_at = None
            if result.returncode == 0:
                expires_line = result.stdout.strip()
                if expires_line.startswith("notAfter="):
                    expires_str = expires_line.replace("notAfter=", "")
                    try:
                        # Try different date formats
                        formats = [
                            "%b %d %H:%M:%S %Y %Z",
                            "%b %d %H:%M:%S %Y GMT",
                            "%Y-%m-%d %H:%M:%S %Z",
                        ]

                        for fmt in formats:
                            try:
                                expires_dt = datetime.strptime(expires_str, fmt)
                                expires_at = expires_dt.isoformat()
                                break
                            except ValueError:
                                continue

                    except Exception as e:
                        print(f"   ⚠️  Could not parse expiration date: {e}")

            # Get subject alternative names (domains covered)
            result = subprocess.run(
                ["openssl", "x509", "-in", cert_file, "-noout", "-text"],
                capture_output=True,
                text=True,
            )

            domains = []
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                for i, line in enumerate(lines):
                    if "Subject Alternative Name:" in line and i + 1 < len(lines):
                        san_line = lines[i + 1].strip()
                        if "DNS:" in san_line:
                            dns_entries = [
                                entry.strip() for entry in san_line.split(",")
                            ]
                            for entry in dns_entries:
                                if entry.startswith("DNS:"):
                                    domain = entry.replace("DNS:", "").strip()
                                    if domain:
                                        domains.append(domain)

            return {"expires_at": expires_at, "domains": domains}

        except Exception as e:
            print(f"   ⚠️  Failed to get certificate info: {e}")
            return None

    def import_existing_certificates(self):
        """Import existing Let's Encrypt certificates"""
        try:
            print("🔍 Scanning for existing SSL certificates...")

            if not os.path.exists(self.letsencrypt_dir):
                print(f"⚠️  Let's Encrypt directory not found: {self.letsencrypt_dir}")
                print(
                    "   This is normal if you haven't installed any SSL certificates yet."
                )
                return True

            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()

            imported_count = 0
            updated_count = 0

            for domain_dir in os.listdir(self.letsencrypt_dir):
                cert_path = os.path.join(self.letsencrypt_dir, domain_dir)

                if not os.path.isdir(cert_path):
                    continue

                cert_file = os.path.join(cert_path, "cert.pem")
                if not os.path.exists(cert_file):
                    print(f"   ⚠️  No cert.pem found in {cert_path}")
                    continue

                print(f"📜 Processing certificate: {domain_dir}")

                # Get certificate information
                cert_info = self.get_certificate_info(cert_file)
                if not cert_info:
                    print(f"   ⚠️  Could not read certificate info")
                    continue

                # Determine certificate type and covered domains
                domains_covered = cert_info.get("domains", [domain_dir])
                cert_type = (
                    "wildcard"
                    if any(d.startswith("*.") for d in domains_covered)
                    else "single"
                )

                # Check if certificate already exists
                cursor.execute(
                    "SELECT id FROM ssl_certificates WHERE domain = ?", (domain_dir,)
                )
                existing = cursor.fetchone()

                cert_paths = {
                    "cert_path": os.path.join(cert_path, "cert.pem"),
                    "privkey_path": os.path.join(cert_path, "privkey.pem"),
                    "fullchain_path": os.path.join(cert_path, "fullchain.pem"),
                    "chain_path": os.path.join(cert_path, "chain.pem"),
                }

                if existing:
                    # Update existing certificate
                    cursor.execute(
                        """
                        UPDATE ssl_certificates SET
                        certificate_type = ?, cert_path = ?, privkey_path = ?, 
                        fullchain_path = ?, chain_path = ?, expires_at = ?, 
                        domains_covered = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE domain = ?
                    """,
                        (
                            cert_type,
                            cert_paths["cert_path"],
                            cert_paths["privkey_path"],
                            cert_paths["fullchain_path"],
                            cert_paths["chain_path"],
                            cert_info.get("expires_at"),
                            json.dumps(domains_covered),
                            domain_dir,
                        ),
                    )
                    updated_count += 1
                    print(
                        f"   ✅ Updated: {domain_dir} ({cert_type}) - expires: {cert_info.get('expires_at')}"
                    )
                else:
                    # Insert new certificate
                    cursor.execute(
                        """
                        INSERT INTO ssl_certificates 
                        (domain, certificate_type, cert_path, privkey_path, fullchain_path, 
                         chain_path, expires_at, domains_covered)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            domain_dir,
                            cert_type,
                            cert_paths["cert_path"],
                            cert_paths["privkey_path"],
                            cert_paths["fullchain_path"],
                            cert_paths["chain_path"],
                            cert_info.get("expires_at"),
                            json.dumps(domains_covered),
                        ),
                    )
                    imported_count += 1
                    print(
                        f"   ✅ Imported: {domain_dir} ({cert_type}) - expires: {cert_info.get('expires_at')}"
                    )

                # Log the import
                cursor.execute(
                    """
                    INSERT INTO ssl_renewal_logs 
                    (domain, action, status, message)
                    VALUES (?, 'import', 'success', 'Certificate imported during setup')
                """,
                    (domain_dir,),
                )

            conn.commit()
            conn.close()

            if imported_count == 0 and updated_count == 0:
                print("📋 No SSL certificates found to import")
            else:
                print(
                    f"📋 Import complete: {imported_count} new, {updated_count} updated"
                )

            return True

        except Exception as e:
            print(f"❌ Certificate import failed: {e}")
            return False

    def list_certificates(self):
        """List all SSL certificates with status"""
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT domain, certificate_type, status, expires_at, domains_covered, created_at
                FROM ssl_certificates 
                WHERE status = 'active'
                ORDER BY expires_at ASC
            """
            )

            certificates = cursor.fetchall()
            conn.close()

            if not certificates:
                print("📋 No SSL certificates found in database")
                return []

            print(f"\n📋 SSL Certificates ({len(certificates)}):")
            print("=" * 70)

            for cert in certificates:
                domain, cert_type, status, expires_at, domains_covered, created_at = (
                    cert
                )

                # Parse domains covered
                try:
                    covered_domains = (
                        json.loads(domains_covered) if domains_covered else [domain]
                    )
                except:
                    covered_domains = [domain]

                # Check if expires soon
                expires_soon = False
                if expires_at:
                    try:
                        expires_dt = datetime.fromisoformat(expires_at)
                        warning_date = datetime.now() + timedelta(days=30)
                        expires_soon = expires_dt <= warning_date
                    except:
                        expires_soon = True

                status_icon = "⚠️ EXPIRES SOON" if expires_soon else "✅ Valid"

                print(f"{status_icon} {domain}")
                print(f"   Type: {cert_type.upper()}")
                print(f"   Status: {status}")
                print(f"   Expires: {expires_at or 'Unknown'}")
                print(f"   Covers: {', '.join(covered_domains)}")
                print(f"   Created: {created_at}")
                print()

            return certificates

        except Exception as e:
            print(f"❌ Failed to list certificates: {e}")
            return []

    def check_certificate_for_domain(self, domain):
        """Check if SSL certificate is available for a specific domain"""
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()

            # Check for exact domain match
            cursor.execute(
                """
                SELECT domain, certificate_type, expires_at, domains_covered, cert_path
                FROM ssl_certificates 
                WHERE domain = ? AND status = 'active'
            """,
                (domain,),
            )

            cert = cursor.fetchone()
            if cert:
                conn.close()
                return {
                    "available": True,
                    "match_type": "exact",
                    "certificate": {
                        "domain": cert[0],
                        "certificate_type": cert[1],
                        "expires_at": cert[2],
                        "domains_covered": json.loads(cert[3]) if cert[3] else [],
                        "cert_path": cert[4],
                    },
                }

            # Check for wildcard certificates that might cover this domain
            domain_parts = domain.split(".")
            if len(domain_parts) > 2:
                wildcard_domain = f"*.{'.'.join(domain_parts[1:])}"

                cursor.execute(
                    """
                    SELECT domain, certificate_type, expires_at, domains_covered, cert_path
                    FROM ssl_certificates 
                    WHERE domains_covered LIKE ? AND status = 'active'
                """,
                    (f"%{wildcard_domain}%",),
                )

                cert = cursor.fetchone()
                if cert:
                    conn.close()
                    return {
                        "available": True,
                        "match_type": "wildcard",
                        "wildcard_pattern": wildcard_domain,
                        "certificate": {
                            "domain": cert[0],
                            "certificate_type": cert[1],
                            "expires_at": cert[2],
                            "domains_covered": json.loads(cert[3]) if cert[3] else [],
                            "cert_path": cert[4],
                        },
                    }

            conn.close()
            return {"available": False}

        except Exception as e:
            print(f"❌ Certificate check failed for {domain}: {e}")
            return {"available": False, "error": str(e)}

    def get_ssl_status_summary(self):
        """Get SSL status summary"""
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()

            # Count certificates
            cursor.execute(
                "SELECT COUNT(*) FROM ssl_certificates WHERE status = 'active'"
            )
            total_certs = cursor.fetchone()[0]

            # Count expiring soon (30 days)
            future_date = (datetime.now() + timedelta(days=30)).isoformat()
            cursor.execute(
                """
                SELECT COUNT(*) FROM ssl_certificates 
                WHERE status = 'active' AND expires_at <= ?
            """,
                (future_date,),
            )
            expiring_soon = cursor.fetchone()[0]

            # Count by type
            cursor.execute(
                """
                SELECT certificate_type, COUNT(*) 
                FROM ssl_certificates 
                WHERE status = 'active' 
                GROUP BY certificate_type
            """
            )
            cert_types = dict(cursor.fetchall())

            conn.close()

            return {
                "total_certificates": total_certs,
                "expiring_soon": expiring_soon,
                "certificate_types": cert_types,
                "status": "healthy" if expiring_soon == 0 else "warning",
            }

        except Exception as e:
            print(f"❌ Failed to get SSL status: {e}")
            return {}

    def complete_setup(self):
        """Run complete SSL system setup"""
        print("🔧 Complete SSL System Setup for Hosting Manager v3.0")
        print("=" * 60)

        success_count = 0
        total_steps = 5

        # Step 1: Install system packages
        print("\n📦 Step 1/5: Installing system packages...")
        if self.install_system_packages():
            success_count += 1

        # Step 2: Install Python packages
        print("\n🐍 Step 2/5: Installing Python packages...")
        if self.install_python_packages():
            success_count += 1

        # Step 3: Setup database
        print("\n🗄️  Step 3/5: Setting up database...")
        if self.setup_database():
            success_count += 1

        # Step 4: Import existing certificates
        print("\n🔍 Step 4/5: Importing existing certificates...")
        if self.import_existing_certificates():
            success_count += 1

        # Step 5: Verify setup
        print("\n✅ Step 5/5: Verifying setup...")
        certificates = self.list_certificates()
        status = self.get_ssl_status_summary()
        success_count += 1

        # Summary
        print(f"\n🎉 SSL System Setup Complete!")
        print(f"   Completed: {success_count}/{total_steps} steps")

        if status:
            print(f"\n📊 SSL Status Summary:")
            print(f"   Total certificates: {status['total_certificates']}")
            print(f"   Expiring soon (30 days): {status['expiring_soon']}")
            print(f"   Certificate types: {status['certificate_types']}")
            print(f"   Overall status: {status['status'].upper()}")

        print(f"\n📋 Next Steps:")
        print(f"   • Test a domain: python3 {sys.argv[0]} --check yourdomain.com")
        print(f"   • List certificates: python3 {sys.argv[0]} --list")
        print(f"   • Check status: python3 {sys.argv[0]} --status")
        print(f"   • Start hosting manager: sudo python3 hosting_manager.py --api")

        return success_count == total_steps


def main():
    """Main function with command-line interface"""
    parser = argparse.ArgumentParser(
        description="Fixed SSL Setup for Hosting Manager v3.0"
    )
    parser.add_argument(
        "--setup", action="store_true", help="Complete SSL system setup"
    )
    parser.add_argument("--list", action="store_true", help="List all SSL certificates")
    parser.add_argument(
        "--check", metavar="DOMAIN", help="Check SSL certificate for specific domain"
    )
    parser.add_argument("--status", action="store_true", help="Show SSL system status")
    parser.add_argument(
        "--install-packages", action="store_true", help="Install packages only"
    )
    parser.add_argument("--setup-db", action="store_true", help="Setup database only")
    parser.add_argument(
        "--import-certs", action="store_true", help="Import certificates only"
    )

    args = parser.parse_args()

    ssl_manager = SSLSetupManager()

    if args.setup:
        success = ssl_manager.complete_setup()
        return 0 if success else 1

    elif args.list:
        ssl_manager.list_certificates()

    elif args.check:
        result = ssl_manager.check_certificate_for_domain(args.check)
        if result["available"]:
            print(f"✅ SSL certificate available for {args.check}")
            cert = result["certificate"]
            print(f"   Match type: {result['match_type']}")
            print(f"   Certificate domain: {cert['domain']}")
            print(f"   Type: {cert['certificate_type']}")
            print(f"   Expires: {cert['expires_at']}")
            print(f"   Covers: {', '.join(cert['domains_covered'])}")
        else:
            print(f"❌ No SSL certificate available for {args.check}")
            if "error" in result:
                print(f"   Error: {result['error']}")

    elif args.status:
        status = ssl_manager.get_ssl_status_summary()
        if status:
            print("📊 SSL System Status:")
            print(f"   Total certificates: {status['total_certificates']}")
            print(f"   Expiring soon: {status['expiring_soon']}")
            print(f"   Types: {status['certificate_types']}")
            print(f"   Status: {status['status'].upper()}")
        else:
            print("❌ Could not get SSL status")

    elif args.install_packages:
        ssl_manager.install_system_packages()
        ssl_manager.install_python_packages()

    elif args.setup_db:
        ssl_manager.setup_database()

    elif args.import_certs:
        ssl_manager.import_existing_certificates()

    else:
        print("Fixed SSL Setup for Hosting Manager v3.0")
        print("=" * 50)
        print("\nCommands:")
        print("  --setup              Complete SSL system setup (recommended)")
        print("  --list               List all SSL certificates")
        print("  --check DOMAIN       Check certificate for domain")
        print("  --status             Show SSL system status")
        print("  --install-packages   Install packages only")
        print("  --setup-db           Setup database only")
        print("  --import-certs       Import certificates only")
        print("\nExample:")
        print("  sudo python3 ssl_setup_fixed.py --setup")
        print("  python3 ssl_setup_fixed.py --check api.smartwave.co.za")

    return 0


if __name__ == "__main__":
    sys.exit(main())
