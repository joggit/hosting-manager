#!/usr/bin/env python3
"""
SSL Manager Module for Hosting Manager v3.1
Complete SSL certificate management with Let's Encrypt integration
"""

import os
import sys
import sqlite3
import subprocess
import json
import requests
from datetime import datetime, timedelta

class SSLManager:
    """SSL Certificate Manager"""
    
    def __init__(self, database_path="/tmp/hosting/hosting.db", ssl_email="admin@smartwave.co.za"):
        self.database_path = database_path
        self.ssl_email = ssl_email
        self.letsencrypt_dir = "/etc/letsencrypt/live"
    
    def get_db_connection(self):
        """Get database connection"""
        try:
            conn = sqlite3.connect(self.database_path, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            return conn
        except Exception as e:
            print(f"Database connection failed: {e}")
            return None
    
    def install_certificate(self, domain, cert_type='single', extra_domains=None):
        """Install SSL certificate using Certbot"""
        try:
            print(f"Installing SSL certificate for {domain}")
            
            cmd = ['certbot', 'certonly', '--nginx', '--non-interactive', '--agree-tos']
            cmd.extend(['--email', self.ssl_email])
            
            if cert_type == 'wildcard':
                cmd.extend(['-d', domain, '-d', f'*.{domain}'])
                cmd.append('--manual')
                cmd.append('--preferred-challenges=dns')
            else:
                cmd.extend(['-d', domain])
                if extra_domains:
                    for extra in extra_domains:
                        cmd.extend(['-d', extra])
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self._import_certificate(domain)
                print(f"✅ SSL certificate installed for {domain}")
                return {'success': True, 'domain': domain}
            else:
                error = result.stderr.strip() or result.stdout.strip()
                print(f"❌ Certbot failed: {error}")
                return {'success': False, 'error': error}
                
        except Exception as e:
            print(f"❌ SSL installation failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _import_certificate(self, domain):
        """Import certificate into database"""
        try:
            cert_path = os.path.join(self.letsencrypt_dir, domain)
            cert_file = os.path.join(cert_path, "cert.pem")
            
            if not os.path.exists(cert_file):
                return False
            
            cert_info = self._get_certificate_info(cert_file)
            if not cert_info:
                return False
            
            domains_covered = cert_info.get('domains', [domain])
            cert_type = 'wildcard' if any(d.startswith('*.') for d in domains_covered) else 'single'
            
            conn = self.get_db_connection()
            if conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO ssl_certificates 
                    (domain, certificate_type, cert_path, privkey_path, fullchain_path, 
                     chain_path, expires_at, domains_covered)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    domain,
                    cert_type,
                    os.path.join(cert_path, "cert.pem"),
                    os.path.join(cert_path, "privkey.pem"),
                    os.path.join(cert_path, "fullchain.pem"),
                    os.path.join(cert_path, "chain.pem"),
                    cert_info.get('expires_at'),
                    json.dumps(domains_covered)
                ))
                
                conn.commit()
                conn.close()
                return True
                
        except Exception as e:
            print(f"Certificate import failed: {e}")
            return False
    
    def _get_certificate_info(self, cert_file):
        """Get certificate information using openssl"""
        try:
            # Get expiration date
            result = subprocess.run([
                'openssl', 'x509', '-in', cert_file, '-noout', '-enddate'
            ], capture_output=True, text=True)
            
            expires_at = None
            if result.returncode == 0:
                expires_line = result.stdout.strip()
                if expires_line.startswith('notAfter='):
                    expires_str = expires_line.replace('notAfter=', '')
                    try:
                        expires_dt = datetime.strptime(expires_str, '%b %d %H:%M:%S %Y %Z')
                        expires_at = expires_dt.isoformat()
                    except:
                        pass
            
            # Get domains covered
            result = subprocess.run([
                'openssl', 'x509', '-in', cert_file, '-noout', '-text'
            ], capture_output=True, text=True)
            
            domains = []
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if 'Subject Alternative Name:' in line and i + 1 < len(lines):
                        san_line = lines[i + 1].strip()
                        if 'DNS:' in san_line:
                            for entry in san_line.split(','):
                                entry = entry.strip()
                                if entry.startswith('DNS:'):
                                    domains.append(entry.replace('DNS:', ''))
            
            return {
                'expires_at': expires_at,
                'domains': domains
            }
            
        except Exception as e:
            print(f"Failed to get certificate info: {e}")
            return None
    
    def check_certificate(self, domain):
        """Check if certificate is available for domain"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return {'available': False, 'error': 'Database connection failed'}
            
            cursor = conn.cursor()
            
            # Check exact match
            cursor.execute("""
                SELECT * FROM ssl_certificates 
                WHERE domain = ? AND status = 'active'
            """, (domain,))
            
            cert = cursor.fetchone()
            if cert:
                return {'available': True, 'certificate': cert}
            
            # Check wildcard match
            domain_parts = domain.split('.')
            if len(domain_parts) > 2:
                wildcard = f"*.{'.'.join(domain_parts[1:])}"
                cursor.execute("""
                    SELECT * FROM ssl_certificates 
                    WHERE domains_covered LIKE ? AND status = 'active'
                """, (f'%{wildcard}%',))
                
                cert = cursor.fetchone()
                if cert:
                    return {'available': True, 'certificate': cert, 'wildcard': True}
            
            conn.close()
            return {'available': False}
            
        except Exception as e:
            print(f"Certificate check failed: {e}")
            return {'available': False, 'error': str(e)}
    
    def list_certificates(self):
        """List all SSL certificates"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return []
            
            cursor = conn.cursor()
            cursor.execute("""
                SELECT domain, certificate_type, status, expires_at, domains_covered, created_at
                FROM ssl_certificates 
                WHERE status = 'active'
                ORDER BY expires_at ASC
            """)
            
            certificates = []
            for row in cursor.fetchall():
                cert = {
                    'domain': row[0],
                    'certificate_type': row[1],
                    'status': row[2],
                    'expires_at': row[3],
                    'domains_covered': json.loads(row[4]) if row[4] else [],
                    'created_at': row[5],
                    'expires_soon': self._expires_soon(row[3])
                }
                certificates.append(cert)
            
            conn.close()
            return certificates
            
        except Exception as e:
            print(f"Failed to list certificates: {e}")
            return []
    
    def _expires_soon(self, expires_at_str, days=30):
        """Check if certificate expires soon"""
        try:
            if not expires_at_str:
                return True
            
            expires_at = datetime.fromisoformat(expires_at_str)
            warning_date = datetime.now() + timedelta(days=days)
            return expires_at <= warning_date
            
        except:
            return True
    
    def import_existing_certificates(self):
        """Import existing Let's Encrypt certificates"""
        try:
            if not os.path.exists(self.letsencrypt_dir):
                print("No Let's Encrypt directory found")
                return False
            
            imported_count = 0
            
            for domain_dir in os.listdir(self.letsencrypt_dir):
                cert_path = os.path.join(self.letsencrypt_dir, domain_dir)
                if os.path.isdir(cert_path):
                    if self._import_certificate(domain_dir):
                        imported_count += 1
                        print(f"✅ Imported: {domain_dir}")
            
            print(f"📋 Imported {imported_count} certificates")
            return True
            
        except Exception as e:
            print(f"Certificate import failed: {e}")
            return False

def main():
    """CLI interface for SSL manager"""
    import argparse
    
    parser = argparse.ArgumentParser(description='SSL Manager for Hosting Manager')
    parser.add_argument('--list', action='store_true', help='List certificates')
    parser.add_argument('--check', help='Check certificate for domain')
    parser.add_argument('--install', help='Install certificate for domain')
    parser.add_argument('--import-certs', action='store_true', help='Import existing certificates')
    parser.add_argument('--type', default='single', choices=['single', 'wildcard'], help='Certificate type')
    
    args = parser.parse_args()
    
    ssl_manager = SSLManager()
    
    if args.list:
        certs = ssl_manager.list_certificates()
        if certs:
            print(f"\n📋 SSL Certificates ({len(certs)}):")
            print("-" * 60)
            for cert in certs:
                status = "⚠️ EXPIRES SOON" if cert['expires_soon'] else "✅ Valid"
                print(f"{status} {cert['domain']}")
                print(f"   Type: {cert['certificate_type']}")
                print(f"   Expires: {cert['expires_at']}")
                print(f"   Covers: {', '.join(cert['domains_covered'])}")
                print()
        else:
            print("No SSL certificates found")
    
    elif args.check:
        result = ssl_manager.check_certificate(args.check)
        if result['available']:
            print(f"✅ SSL certificate available for {args.check}")
        else:
            print(f"❌ No SSL certificate available for {args.check}")
    
    elif args.install:
        result = ssl_manager.install_certificate(args.install, args.type)
        if result['success']:
            print(f"✅ SSL certificate installed for {args.install}")
        else:
            print(f"❌ Failed to install certificate: {result['error']}")
    
    elif args.import_certs:
        ssl_manager.import_existing_certificates()
    
    else:
        print("SSL Manager for Hosting Manager")
        print("Usage:")
        print("  --list                  List all certificates")
        print("  --check domain.com      Check certificate for domain")
        print("  --install domain.com    Install certificate for domain")
        print("  --import-certs          Import existing certificates")

if __name__ == "__main__":
    main()
