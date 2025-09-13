# src/hosting/ssl_manager.py
"""
SSL Certificate Management System
Handles certificate installation, renewal, and tracking with database persistence
"""

import os
import json
import subprocess
import sqlite3
import ssl
import socket
from datetime import datetime, timedelta
from pathlib import Path
import logging


class SSLCertificateManager:
    """Centralized SSL certificate management with database tracking"""

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.ssl_cert_path = "/etc/letsencrypt/live"
        self.ssl_config_path = "/etc/letsencrypt"
        self.ssl_email = config.get("ssl_email", "admin@localhost")

    def setup_database(self, db_connection):
        """Setup SSL certificate tracking tables"""
        try:
            cursor = db_connection.cursor()

            # SSL Certificates table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ssl_certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    certificate_type TEXT NOT NULL DEFAULT 'single', -- single, wildcard, multi-domain
                    certificate_path TEXT,
                    private_key_path TEXT,
                    fullchain_path TEXT,
                    issuer TEXT DEFAULT 'letsencrypt',
                    status TEXT DEFAULT 'pending', -- pending, active, expired, failed, revoked
                    issued_at TIMESTAMP,
                    expires_at TIMESTAMP,
                    last_renewal_attempt TIMESTAMP,
                    renewal_failures INTEGER DEFAULT 0,
                    auto_renew BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Certificate domains mapping (for multi-domain and wildcard certs)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS certificate_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    certificate_id INTEGER,
                    domain_name TEXT NOT NULL,
                    is_primary BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (certificate_id) REFERENCES ssl_certificates (id) ON DELETE CASCADE
                )
            """
            )

            # Certificate renewal log
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS certificate_renewal_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    certificate_id INTEGER,
                    renewal_type TEXT, -- manual, auto, forced
                    status TEXT, -- success, failed, skipped
                    old_expires_at TIMESTAMP,
                    new_expires_at TIMESTAMP,
                    error_message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (certificate_id) REFERENCES ssl_certificates (id) ON DELETE CASCADE
                )
            """
            )

            db_connection.commit()
            self.logger.info("SSL certificate management database initialized")
            return True

        except Exception as e:
            self.logger.error(f"Failed to setup SSL certificate database: {e}")
            return False

    def install_certificate(
        self, domain, certificate_type="single", extra_domains=None
    ):
        """Install SSL certificate for a domain"""
        try:
            self.logger.info(
                f"Installing SSL certificate for {domain} (type: {certificate_type})"
            )

            # Check if certificate already exists and is valid
            existing_cert = self.get_certificate_info(domain)
            if existing_cert and existing_cert["status"] == "active":
                if self._is_certificate_valid(existing_cert):
                    self.logger.info(f"Valid certificate already exists for {domain}")
                    return {
                        "success": True,
                        "message": "Certificate already exists and is valid",
                        "certificate": existing_cert,
                    }

            # Prepare domain list for certificate
            domain_list = [domain]
            if extra_domains:
                domain_list.extend(extra_domains)

            # For wildcard certificates
            if certificate_type == "wildcard":
                wildcard_domain = f"*.{domain}"
                domain_list = [domain, wildcard_domain]

            # Create certificate using certbot
            result = self._create_certificate(domain_list, certificate_type)

            if result["success"]:
                # Store certificate info in database
                cert_id = self._store_certificate_info(
                    domain, certificate_type, domain_list, result["paths"]
                )

                if cert_id:
                    self.logger.info(
                        f"SSL certificate installed successfully for {domain}"
                    )
                    return {
                        "success": True,
                        "certificate_id": cert_id,
                        "paths": result["paths"],
                        "domains": domain_list,
                    }
                else:
                    return {
                        "success": False,
                        "error": "Failed to store certificate info",
                    }
            else:
                return {"success": False, "error": result["error"]}

        except Exception as e:
            self.logger.error(f"Failed to install certificate for {domain}: {e}")
            return {"success": False, "error": str(e)}

    def _create_certificate(self, domain_list, certificate_type):
        """Create SSL certificate using certbot"""
        try:
            primary_domain = domain_list[0]

            # Build certbot command
            cmd = [
                "certbot",
                "certonly",
                "--nginx",
                "--non-interactive",
                "--agree-tos",
                "--email",
                self.ssl_email,
                "--cert-name",
                primary_domain,
            ]

            # Add all domains
            for domain in domain_list:
                cmd.extend(["-d", domain])

            # For wildcard certificates, use DNS challenge
            if certificate_type == "wildcard":
                cmd = [
                    "certbot",
                    "certonly",
                    "--manual",
                    "--preferred-challenges=dns",
                    "--non-interactive",
                    "--agree-tos",
                    "--email",
                    self.ssl_email,
                    "--cert-name",
                    primary_domain,
                    "--manual-public-ip-logging-ok",
                ]
                for domain in domain_list:
                    cmd.extend(["-d", domain])

            self.logger.info(f"Running certbot command: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                # Get certificate paths
                cert_dir = f"{self.ssl_cert_path}/{primary_domain}"

                paths = {
                    "cert_path": f"{cert_dir}/cert.pem",
                    "privkey_path": f"{cert_dir}/privkey.pem",
                    "fullchain_path": f"{cert_dir}/fullchain.pem",
                    "chain_path": f"{cert_dir}/chain.pem",
                }

                # Verify files exist
                for path_type, path in paths.items():
                    if not os.path.exists(path):
                        return {
                            "success": False,
                            "error": f"Certificate file not found: {path}",
                        }

                return {"success": True, "paths": paths}
            else:
                error_msg = result.stderr or result.stdout
                self.logger.error(f"Certbot failed: {error_msg}")
                return {"success": False, "error": error_msg}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Certificate creation timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _store_certificate_info(self, domain, certificate_type, domain_list, paths):
        """Store certificate information in database"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            # Get certificate expiration date
            expires_at = self._get_certificate_expiry(paths["fullchain_path"])

            # Insert or update certificate record
            cursor.execute(
                """
                INSERT OR REPLACE INTO ssl_certificates (
                    domain, certificate_type, certificate_path, private_key_path, 
                    fullchain_path, status, issued_at, expires_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
                (
                    domain,
                    certificate_type,
                    paths["cert_path"],
                    paths["privkey_path"],
                    paths["fullchain_path"],
                    "active",
                    datetime.now(),
                    expires_at,
                ),
            )

            cert_id = cursor.lastrowid

            # Clear existing domain mappings
            cursor.execute(
                "DELETE FROM certificate_domains WHERE certificate_id = ?", (cert_id,)
            )

            # Store domain mappings
            for i, domain_name in enumerate(domain_list):
                cursor.execute(
                    """
                    INSERT INTO certificate_domains (certificate_id, domain_name, is_primary)
                    VALUES (?, ?, ?)
                """,
                    (cert_id, domain_name, i == 0),
                )

            conn.commit()
            conn.close()

            return cert_id

        except Exception as e:
            self.logger.error(f"Failed to store certificate info: {e}")
            return None

    def get_certificate_info(self, domain):
        """Get certificate information for a domain"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT c.*, GROUP_CONCAT(cd.domain_name) as all_domains
                FROM ssl_certificates c
                LEFT JOIN certificate_domains cd ON c.id = cd.certificate_id
                WHERE c.domain = ? OR cd.domain_name = ?
                GROUP BY c.id
                ORDER BY c.created_at DESC
                LIMIT 1
            """,
                (domain, domain),
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
                    "issuer": result[6],
                    "status": result[7],
                    "issued_at": result[8],
                    "expires_at": result[9],
                    "last_renewal_attempt": result[10],
                    "renewal_failures": result[11],
                    "auto_renew": result[12],
                    "all_domains": result[15].split(",") if result[15] else [],
                }
            return None

        except Exception as e:
            self.logger.error(f"Failed to get certificate info: {e}")
            return None

    def check_certificate_for_domain(self, domain):
        """Check if a valid certificate exists for a domain"""
        try:
            # Check for exact match
            cert_info = self.get_certificate_info(domain)
            if cert_info and cert_info["status"] == "active":
                if self._is_certificate_valid(cert_info):
                    return {
                        "available": True,
                        "certificate": cert_info,
                        "paths": {
                            "fullchain": cert_info["fullchain_path"],
                            "privkey": cert_info["private_key_path"],
                        },
                    }

            # Check for wildcard certificate
            domain_parts = domain.split(".")
            if len(domain_parts) > 2:  # subdomain.example.com
                parent_domain = ".".join(domain_parts[1:])  # example.com
                wildcard_cert = self.get_certificate_info(parent_domain)

                if wildcard_cert and wildcard_cert["certificate_type"] == "wildcard":
                    if self._is_certificate_valid(wildcard_cert):
                        return {
                            "available": True,
                            "certificate": wildcard_cert,
                            "paths": {
                                "fullchain": wildcard_cert["fullchain_path"],
                                "privkey": wildcard_cert["private_key_path"],
                            },
                        }

            return {"available": False}

        except Exception as e:
            self.logger.error(f"Failed to check certificate for {domain}: {e}")
            return {"available": False}

    def _is_certificate_valid(self, cert_info):
        """Check if certificate is still valid"""
        try:
            # Check if files exist
            if not os.path.exists(cert_info["fullchain_path"]):
                return False
            if not os.path.exists(cert_info["private_key_path"]):
                return False

            # Check expiration date
            expires_at = datetime.fromisoformat(
                cert_info["expires_at"].replace("Z", "+00:00")
            )
            days_until_expiry = (expires_at - datetime.now()).days

            # Consider valid if more than 7 days until expiry
            return days_until_expiry > 7

        except Exception as e:
            self.logger.error(f"Failed to validate certificate: {e}")
            return False

    def _get_certificate_expiry(self, cert_path):
        """Get certificate expiration date"""
        try:
            result = subprocess.run(
                ["openssl", "x509", "-in", cert_path, "-noout", "-enddate"],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                # Parse: notAfter=Dec 30 23:59:59 2024 GMT
                date_str = result.stdout.strip().split("=")[1]
                return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")

            return None

        except Exception as e:
            self.logger.error(f"Failed to get certificate expiry: {e}")
            return None

    def list_certificates(self, include_expired=False):
        """List all certificates"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            query = """
                SELECT c.*, GROUP_CONCAT(cd.domain_name) as all_domains
                FROM ssl_certificates c
                LEFT JOIN certificate_domains cd ON c.id = cd.certificate_id
            """

            if not include_expired:
                query += " WHERE c.status = 'active'"

            query += " GROUP BY c.id ORDER BY c.created_at DESC"

            cursor.execute(query)
            results = cursor.fetchall()
            conn.close()

            certificates = []
            for row in results:
                cert = {
                    "id": row[0],
                    "domain": row[1],
                    "certificate_type": row[2],
                    "status": row[7],
                    "issued_at": row[8],
                    "expires_at": row[9],
                    "domains": row[15].split(",") if row[15] else [],
                }

                # Add validity status
                cert["is_valid"] = (
                    self._is_certificate_valid(row) if row[7] == "active" else False
                )
                certificates.append(cert)

            return certificates

        except Exception as e:
            self.logger.error(f"Failed to list certificates: {e}")
            return []

    def renew_certificate(self, domain, force=False):
        """Renew SSL certificate"""
        try:
            cert_info = self.get_certificate_info(domain)
            if not cert_info:
                return {"success": False, "error": "Certificate not found"}

            # Check if renewal is needed
            if not force and self._is_certificate_valid(cert_info):
                return {"success": True, "message": "Certificate is still valid"}

            self.logger.info(f"Renewing certificate for {domain}")

            # Run certbot renewal
            cmd = ["certbot", "renew", "--cert-name", domain, "--nginx"]
            if force:
                cmd.append("--force-renewal")

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                # Update database
                conn = self.get_db_connection()
                cursor = conn.cursor()

                new_expires_at = self._get_certificate_expiry(
                    cert_info["fullchain_path"]
                )

                cursor.execute(
                    """
                    UPDATE ssl_certificates 
                    SET expires_at = ?, last_renewal_attempt = CURRENT_TIMESTAMP, 
                        renewal_failures = 0, updated_at = CURRENT_TIMESTAMP
                    WHERE domain = ?
                """,
                    (new_expires_at, domain),
                )

                # Log renewal
                cursor.execute(
                    """
                    INSERT INTO certificate_renewal_log 
                    (certificate_id, renewal_type, status, old_expires_at, new_expires_at)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (
                        cert_info["id"],
                        "manual" if force else "auto",
                        "success",
                        cert_info["expires_at"],
                        new_expires_at,
                    ),
                )

                conn.commit()
                conn.close()

                return {"success": True, "new_expiry": new_expires_at}
            else:
                error_msg = result.stderr or result.stdout

                # Update failure count
                conn = self.get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE ssl_certificates 
                    SET last_renewal_attempt = CURRENT_TIMESTAMP, 
                        renewal_failures = renewal_failures + 1
                    WHERE domain = ?
                """,
                    (domain,),
                )

                # Log failure
                cursor.execute(
                    """
                    INSERT INTO certificate_renewal_log 
                    (certificate_id, renewal_type, status, error_message)
                    VALUES (?, ?, ?, ?)
                """,
                    (
                        cert_info["id"],
                        "manual" if force else "auto",
                        "failed",
                        error_msg,
                    ),
                )

                conn.commit()
                conn.close()

                return {"success": False, "error": error_msg}

        except Exception as e:
            self.logger.error(f"Failed to renew certificate for {domain}: {e}")
            return {"success": False, "error": str(e)}

    def auto_renew_certificates(self):
        """Automatically renew certificates that are expiring soon"""
        try:
            certificates = self.list_certificates()
            renewed = 0
            failed = 0

            for cert in certificates:
                if cert["auto_renew"] and not cert["is_valid"]:
                    result = self.renew_certificate(cert["domain"])
                    if result["success"]:
                        renewed += 1
                    else:
                        failed += 1

            return {
                "success": True,
                "renewed": renewed,
                "failed": failed,
                "message": f"Renewed {renewed} certificates, {failed} failures",
            }

        except Exception as e:
            self.logger.error(f"Auto renewal failed: {e}")
            return {"success": False, "error": str(e)}

    def delete_certificate(self, domain):
        """Delete SSL certificate"""
        try:
            cert_info = self.get_certificate_info(domain)
            if not cert_info:
                return {"success": False, "error": "Certificate not found"}

            # Revoke certificate with certbot
            result = subprocess.run(
                ["certbot", "delete", "--cert-name", domain, "--non-interactive"],
                capture_output=True,
                text=True,
            )

            # Remove from database regardless of certbot result
            conn = self.get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM ssl_certificates WHERE domain = ?", (domain,))
            conn.commit()
            conn.close()

            if result.returncode == 0:
                return {"success": True, "message": "Certificate deleted successfully"}
            else:
                return {
                    "success": True,
                    "message": "Certificate removed from database (certbot deletion may have failed)",
                }

        except Exception as e:
            self.logger.error(f"Failed to delete certificate for {domain}: {e}")
            return {"success": False, "error": str(e)}

    def get_db_connection(self):
        """Get database connection"""
        db_path = self.config.get("database_path", "/tmp/hosting/hosting.db")
        return sqlite3.connect(db_path, timeout=30.0)
