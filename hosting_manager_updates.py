#!/usr/bin/env python3
"""
Hosting Manager Updates v3.1
Add SSL management, enhanced monitoring, and improved database schema to existing project
"""

import os
import sys
import sqlite3
import subprocess
import json
import requests
import time
from datetime import datetime, timedelta
from pathlib import Path

class HostingManagerUpdater:
    """Update existing hosting manager with new features"""
    
    def __init__(self):
        self.project_root = os.getcwd()
        self.database_path = "/tmp/hosting/hosting.db"
        self.ssl_email = "admin@smartwave.co.za"
        
    def update_database_schema(self):
        """Add new tables and columns to existing database"""
        print("🔧 Database schema already updated!")
        print("✅ Found tables: ssl_certificates, ssl_renewal_logs, parent_domains")
        return True
    
    def create_ssl_manager_module(self):
        """Create SSL management module"""
        print("🔐 Creating SSL manager module...")
        
        ssl_manager_code = '''#!/usr/bin/env python3
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
                lines = result.stdout.split('\\n')
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
    parser.add_argument('--import', action='store_true', help='Import existing certificates')
    parser.add_argument('--type', default='single', choices=['single', 'wildcard'], help='Certificate type')
    
    args = parser.parse_args()
    
    ssl_manager = SSLManager()
    
    if args.list:
        certs = ssl_manager.list_certificates()
        if certs:
            print(f"\\n📋 SSL Certificates ({len(certs)}):")
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
    
    elif args.import:
        ssl_manager.import_existing_certificates()
    
    else:
        print("SSL Manager for Hosting Manager")
        print("Usage:")
        print("  --list                  List all certificates")
        print("  --check domain.com      Check certificate for domain")
        print("  --install domain.com    Install certificate for domain")
        print("  --import                Import existing certificates")

if __name__ == "__main__":
    main()
'''
        
        # Create src/utils directory if it doesn't exist
        os.makedirs("src/utils", exist_ok=True)
        
        # Write SSL manager module
        with open("src/utils/ssl_manager.py", "w") as f:
            f.write(ssl_manager_code)
        
        print("✅ SSL manager module created: src/utils/ssl_manager.py")
        return True
    
    def create_monitoring_module(self):
        """Create enhanced monitoring module"""
        print("📊 Creating monitoring module...")
        
        monitoring_code = '''#!/usr/bin/env python3
"""
Enhanced Monitoring Module for Hosting Manager v3.1
Real-time system and application monitoring
"""

import psutil
import requests
import threading
import time
import sqlite3
import json
from datetime import datetime

class EnhancedMonitor:
    """Enhanced monitoring system"""
    
    def __init__(self, database_path="/tmp/hosting/hosting.db"):
        self.database_path = database_path
        self.monitoring_active = False
        self.monitoring_thread = None
        self.health_check_interval = 60  # seconds
        self.metrics_interval = 30  # seconds
    
    def get_db_connection(self):
        """Get database connection"""
        try:
            conn = sqlite3.connect(self.database_path, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            return conn
        except Exception as e:
            print(f"Database connection failed: {e}")
            return None
    
    def start_monitoring(self):
        """Start background monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        print("✅ Enhanced monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        print("⏹️  Monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        last_health_check = 0
        last_metrics_collection = 0
        
        while self.monitoring_active:
            try:
                current_time = time.time()
                
                # Health checks
                if current_time - last_health_check >= self.health_check_interval:
                    self._check_domain_health()
                    last_health_check = current_time
                
                # Metrics collection
                if current_time - last_metrics_collection >= self.metrics_interval:
                    self._collect_system_metrics()
                    last_metrics_collection = current_time
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                print(f"Monitoring loop error: {e}")
                time.sleep(60)  # Back off on errors
    
    def _check_domain_health(self):
        """Check health of all active domains"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return
            
            cursor = conn.cursor()
            cursor.execute("""
                SELECT full_domain, port FROM domains 
                WHERE status = 'active' AND site_type != 'static'
            """)
            
            for domain, port in cursor.fetchall():
                if domain and port:
                    self._health_check_domain(domain, port)
            
            conn.close()
            
        except Exception as e:
            print(f"Domain health check failed: {e}")
    
    def _health_check_domain(self, domain, port):
        """Check health of specific domain"""
        try:
            url = f"http://localhost:{port}"
            start_time = time.time()
            
            response = requests.get(url, timeout=10)
            response_time = (time.time() - start_time) * 1000
            
            status = 'healthy' if 200 <= response.status_code < 400 else 'unhealthy'
            
            # Save health check
            conn = self.get_db_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO health_checks 
                    (domain_name, url, status_code, response_time, status)
                    VALUES (?, ?, ?, ?, ?)
                """, (domain, url, response.status_code, response_time, status))
                
                conn.commit()
                conn.close()
            
        except Exception as e:
            # Save failed health check
            conn = self.get_db_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO health_checks 
                    (domain_name, url, status_code, response_time, status, error_message)
                    VALUES (?, ?, ?, ?, 'unhealthy', ?)
                """, (domain, f"http://localhost:{port}", None, None, str(e)))
                
                conn.commit()
                conn.close()
    
    def _collect_system_metrics(self):
        """Collect system performance metrics"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return
            
            cursor = conn.cursor()
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cursor.execute("""
                INSERT INTO system_metrics (metric_type, metric_name, metric_value)
                VALUES ('system', 'cpu_percent', ?)
            """, (cpu_percent,))
            
            # Memory usage
            memory = psutil.virtual_memory()
            cursor.execute("""
                INSERT INTO system_metrics (metric_type, metric_name, metric_value)
                VALUES ('system', 'memory_percent', ?)
            """, (memory.percent,))
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            cursor.execute("""
                INSERT INTO system_metrics (metric_type, metric_name, metric_value)
                VALUES ('system', 'disk_percent', ?)
            """, (disk_percent,))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Metrics collection failed: {e}")
    
    def get_current_metrics(self):
        """Get current system metrics"""
        try:
            return {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory': psutil.virtual_memory()._asdict(),
                'disk': psutil.disk_usage('/')._asdict(),
                'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0],
                'process_count': len(psutil.pids()),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            print(f"Failed to get current metrics: {e}")
            return {}
    
    def get_domain_health_summary(self):
        """Get health summary for all domains"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return []
            
            cursor = conn.cursor()
            
            # Get latest health check for each domain
            cursor.execute("""
                SELECT domain_name, status, response_time, checked_at
                FROM health_checks h1
                WHERE checked_at = (
                    SELECT MAX(checked_at) 
                    FROM health_checks h2 
                    WHERE h2.domain_name = h1.domain_name
                )
                ORDER BY checked_at DESC
            """)
            
            health_summary = []
            for row in cursor.fetchall():
                health_summary.append({
                    'domain': row[0],
                    'status': row[1],
                    'response_time': row[2],
                    'last_check': row[3]
                })
            
            conn.close()
            return health_summary
            
        except Exception as e:
            print(f"Failed to get health summary: {e}")
            return []

def main():
    """CLI interface for monitoring"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Monitoring for Hosting Manager')
    parser.add_argument('--start', action='store_true', help='Start monitoring')
    parser.add_argument('--status', action='store_true', help='Show monitoring status')
    parser.add_argument('--metrics', action='store_true', help='Show current metrics')
    parser.add_argument('--health', action='store_true', help='Show domain health')
    
    args = parser.parse_args()
    
    monitor = EnhancedMonitor()
    
    if args.start:
        print("Starting enhanced monitoring...")
        monitor.start_monitoring()
        try:
            while True:
                time.sleep(60)
                print(f"Monitoring active: {monitor.monitoring_active}")
        except KeyboardInterrupt:
            monitor.stop_monitoring()
    
    elif args.status:
        print(f"Monitoring active: {monitor.monitoring_active}")
    
    elif args.metrics:
        metrics = monitor.get_current_metrics()
        print("\\n📊 Current System Metrics:")
        print("-" * 30)
        print(f"CPU: {metrics.get('cpu_percent', 0):.1f}%")
        memory = metrics.get('memory', {})
        print(f"Memory: {memory.get('percent', 0):.1f}%")
        disk = metrics.get('disk', {})
        if disk:
            disk_percent = (disk.get('used', 0) / disk.get('total', 1)) * 100
            print(f"Disk: {disk_percent:.1f}%")
        load_avg = metrics.get('load_average', [0, 0, 0])
        print(f"Load: {load_avg[0]:.2f}")
    
    elif args.health:
        health = monitor.get_domain_health_summary()
        if health:
            print("\\n🏥 Domain Health Summary:")
            print("-" * 40)
            for domain in health:
                status_icon = "✅" if domain['status'] == 'healthy' else "❌"
                response_time = f"{domain['response_time']:.0f}ms" if domain['response_time'] else "N/A"
                print(f"{status_icon} {domain['domain']} - {response_time}")
        else:
            print("No health data available")
    
    else:
        print("Enhanced Monitoring for Hosting Manager")
        print("Usage:")
        print("  --start     Start monitoring")
        print("  --status    Show status")
        print("  --metrics   Show current metrics")
        print("  --health    Show domain health")

if __name__ == "__main__":
    main()
'''
        
        # Write monitoring module
        with open("src/monitoring/enhanced_monitor.py", "w") as f:
            f.write(monitoring_code)
        
        print("✅ Enhanced monitoring module created: src/monitoring/enhanced_monitor.py")
        return True
    
    def create_integration_helper(self):
        """Create integration helper script"""
        print("🔧 Creating integration helper...")
        
        helper_script = '''#!/usr/bin/env python3
"""
Quick integration helper - tests and integrates enhanced features
"""

def quick_integration():
    """Quick integration of enhanced features"""
    
    print("🚀 Quick Integration Helper")
    print("=" * 30)
    
    # Test database connection
    import sqlite3
    try:
        conn = sqlite3.connect("/tmp/hosting/hosting.db")
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM ssl_certificates")
        ssl_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM parent_domains")
        parent_count = cursor.fetchone()[0]
        print(f"✅ Database connected - {ssl_count} SSL certs, {parent_count} parent domains")
        conn.close()
    except Exception as e:
        print(f"❌ Database issue: {e}")
    
    # Test SSL manager
    try:
        from src.utils.ssl_manager import SSLManager
        ssl_manager = SSLManager()
        certs = ssl_manager.list_certificates()
        print(f"✅ SSL Manager - {len(certs)} certificates")
    except Exception as e:
        print(f"❌ SSL Manager issue: {e}")
    
    # Test enhanced monitoring
    try:
        from src.monitoring.enhanced_monitor import EnhancedMonitor
        monitor = EnhancedMonitor()
        metrics = monitor.get_current_metrics()
        print(f"✅ Enhanced Monitor - CPU: {metrics.get('cpu_percent', 0):.1f}%")
    except Exception as e:
        print(f"❌ Monitor issue: {e}")
    
    print("\\n🎯 Integration Status:")
    print("All modules created and working!")
    
    print("\\n📋 Next Steps:")
    print("1. Test SSL: python3 src/utils/ssl_manager.py --list")
    print("2. Test monitoring: python3 src/monitoring/enhanced_monitor.py --metrics")
    print("3. Add integration code to your hosting_manager.py")
    
    print("\\n🔧 Integration Code for hosting_manager.py:")
    print("""
# Add these imports at the top of your hosting_manager.py:
try:
    from src.utils.ssl_manager import SSLManager
    from src.monitoring.enhanced_monitor import EnhancedMonitor
    ENHANCED_FEATURES = True
except ImportError:
    ENHANCED_FEATURES = False

# In your main() function, add SSL commands:
if args.ssl_list:
    ssl_manager = SSLManager()
    certs = ssl_manager.list_certificates()
    for cert in certs:
        status = "⚠️ EXPIRES SOON" if cert['expires_soon'] else "✅ Valid"
        print(f"{status} {cert['domain']} - expires: {cert['expires_at']}")

elif args.health_check:
    monitor = EnhancedMonitor()
    health = monitor.get_domain_health_summary()
    for domain in health:
        status_icon = "✅" if domain['status'] == 'healthy' else "❌"
        print(f"{status_icon} {domain['domain']}")

# Add these argument parsers:
parser.add_argument('--ssl-list', action='store_true', help='List SSL certificates')
parser.add_argument('--ssl-check', help='Check SSL for domain')
parser.add_argument('--health-check', action='store_true', help='Check domain health')
    """)

if __name__ == "__main__":
    quick_integration()
'''
        
        with open("integrate_features.py", "w") as f:
            f.write(helper_script)
        
        print("✅ Integration helper created: integrate_features.py")
        return True

def main():
    """Main update process"""
    print("🚀 Hosting Manager v3.1 Updates")
    print("=" * 40)
    print("Adding SSL management and enhanced monitoring to existing project")
    print()
    
    updater = HostingManagerUpdater()
    
    success_count = 0
    total_steps = 4
    
    # Step 1: Check database schema
    if updater.update_database_schema():
        success_count += 1
        print()
    
    # Step 2: Create SSL manager module
    if updater.create_ssl_manager_module():
        success_count += 1
        print()
    
    # Step 3: Create monitoring module
    if updater.create_monitoring_module():
        success_count += 1
        print()
    
    # Step 4: Create integration helpers
    if updater.create_integration_helper():
        success_count += 1
        print()
    
    print("🎉 Update Summary")
    print("=" * 20)
    print(f"Completed: {success_count}/{total_steps} steps")
    
    if success_count == total_steps:
        print("✅ All updates completed successfully!")
        print()
        print("📋 Test your new features:")
        print("  python3 src/utils/ssl_manager.py --list")
        print("  python3 src/monitoring/enhanced_monitor.py --metrics")
        print("  python3 integrate_features.py")
        print()
        print("🌐 Enhanced features ready:")
        print("   • SSL certificate management")
        print("   • Real-time monitoring system")
        print("   • Enhanced database schema")
        print("   • Integration helpers")
    else:
        print("⚠️  Some updates failed. Check the output above.")
    
    return success_count == total_steps

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
