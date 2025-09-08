#!/usr/bin/env python3
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
        print("\n📊 Current System Metrics:")
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
            print("\n🏥 Domain Health Summary:")
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
