# Create the missing health checker file

# src/monitoring/health_checker.py
"""
Health monitoring system for deployed applications
Monitors HTTP endpoints, response times, and service availability
"""

import requests
import threading
import time
import json
import os
from datetime import datetime, timedelta


class HealthChecker:
    """Health monitoring system for deployed applications"""

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.health_checks = {}
        self.monitoring_thread = None
        self.monitoring_active = False
        self.check_interval = config.get("health_check_interval", 60)  # seconds

    def setup(self):
        """Setup health monitoring system"""
        try:
            self.logger.info("Setting up health checker...")

            # Create monitoring directory
            os.makedirs("/tmp/monitoring", mode=0o755, exist_ok=True)

            # Load existing health checks from database
            self._load_health_checks_from_db()

            self.logger.info(
                f"Health checker setup completed - monitoring {len(self.health_checks)} services"
            )
            return True

        except Exception as e:
            self.logger.error(f"Health checker setup failed: {e}")
            return False

    def _load_health_checks_from_db(self):
        """Load health checks from database"""
        try:
            # Get database connection from hosting manager
            conn = self._get_db_connection()
            if conn:
                cursor = conn.cursor()

                # Get active domains that need health checks
                cursor.execute(
                    """
                    SELECT domain_name, port, site_type 
                    FROM domains 
                    WHERE status = 'active' AND site_type != 'static'
                """
                )

                for row in cursor.fetchall():
                    domain_name, port, site_type = row
                    url = f"http://localhost:{port}"
                    self.add_health_check(domain_name, url)

                conn.close()

        except Exception as e:
            self.logger.error(f"Failed to load health checks from DB: {e}")

    def add_health_check(self, name, url, timeout=10, expected_status=200):
        """Add a new health check"""
        try:
            self.health_checks[name] = {
                "url": url,
                "timeout": timeout,
                "expected_status": expected_status,
                "last_check": None,
                "last_status": "unknown",
                "last_response_time": None,
                "consecutive_failures": 0,
                "total_checks": 0,
                "successful_checks": 0,
                "created_at": datetime.now().isoformat(),
            }

            self.logger.info(f"Added health check: {name} -> {url}")

        except Exception as e:
            self.logger.error(f"Failed to add health check for {name}: {e}")

    def remove_health_check(self, name):
        """Remove a health check"""
        if name in self.health_checks:
            del self.health_checks[name]
            self.logger.info(f"Removed health check: {name}")

    def check_health(self, name):
        """Perform health check for a specific service"""
        if name not in self.health_checks:
            return None

        check_config = self.health_checks[name]

        try:
            start_time = time.time()

            response = requests.get(
                check_config["url"],
                timeout=check_config["timeout"],
                allow_redirects=True,
            )

            response_time = (time.time() - start_time) * 1000  # ms

            # Determine if healthy
            is_healthy = (
                response.status_code == check_config["expected_status"]
                or 200 <= response.status_code < 400
            )

            # Update check data
            check_config["last_check"] = datetime.now().isoformat()
            check_config["last_response_time"] = round(response_time, 2)
            check_config["total_checks"] += 1

            if is_healthy:
                check_config["last_status"] = "healthy"
                check_config["successful_checks"] += 1
                check_config["consecutive_failures"] = 0
            else:
                check_config["last_status"] = "unhealthy"
                check_config["consecutive_failures"] += 1

            # Log to database
            self._log_health_check(
                name, check_config, response.status_code, response_time
            )

            return {
                "name": name,
                "status": check_config["last_status"],
                "status_code": response.status_code,
                "response_time": response_time,
                "url": check_config["url"],
                "timestamp": check_config["last_check"],
            }

        except requests.exceptions.RequestException as e:
            # Handle network/connection errors
            check_config["last_check"] = datetime.now().isoformat()
            check_config["last_status"] = "unhealthy"
            check_config["consecutive_failures"] += 1
            check_config["total_checks"] += 1

            self._log_health_check(name, check_config, None, None, str(e))

            return {
                "name": name,
                "status": "unhealthy",
                "error": str(e),
                "url": check_config["url"],
                "timestamp": check_config["last_check"],
            }

        except Exception as e:
            self.logger.error(f"Health check failed for {name}: {e}")
            return None

    def get_domain_health(self, domain_name):
        """Get health status for a specific domain"""
        if domain_name in self.health_checks:
            check_config = self.health_checks[domain_name]

            return {
                "status": check_config["last_status"],
                "last_check": check_config["last_check"],
                "response_time": check_config["last_response_time"],
                "consecutive_failures": check_config["consecutive_failures"],
                "uptime_percentage": self._calculate_uptime(check_config),
            }

        return {"status": "not_monitored"}

    def get_process_health(self, process_name):
        """Get health data for a specific process"""
        return self.get_domain_health(process_name)

    def get_all_health_data(self):
        """Get health data for all monitored services"""
        health_data = []

        for name, check_config in self.health_checks.items():
            health_info = {
                "name": name,
                "url": check_config["url"],
                "status": check_config["last_status"],
                "last_check": check_config["last_check"],
                "response_time": check_config["last_response_time"],
                "consecutive_failures": check_config["consecutive_failures"],
                "total_checks": check_config["total_checks"],
                "successful_checks": check_config["successful_checks"],
                "uptime_percentage": self._calculate_uptime(check_config),
            }
            health_data.append(health_info)

        return health_data

    def _calculate_uptime(self, check_config):
        """Calculate uptime percentage"""
        total = check_config["total_checks"]
        successful = check_config["successful_checks"]

        if total == 0:
            return 100.0

        return round((successful / total) * 100, 2)

    def start_background_checks(self):
        """Start background health checking"""
        if self.monitoring_active:
            return

        def health_check_loop():
            while self.monitoring_active:
                try:
                    self.check_all_health()
                    time.sleep(self.check_interval)
                except Exception as e:
                    self.logger.error(f"Health check loop error: {e}")
                    time.sleep(60)  # Back off on errors

        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=health_check_loop, daemon=True)
        self.monitoring_thread.start()

        self.logger.info(
            f"Background health checking started (interval: {self.check_interval}s)"
        )

    def stop_background_checks(self):
        """Stop background health checking"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        self.logger.info("Background health checking stopped")

    def is_active(self):
        """Check if health monitoring is active"""
        return (
            self.monitoring_active
            and self.monitoring_thread
            and self.monitoring_thread.is_alive()
        )

    def get_last_check_time(self):
        """Get the timestamp of the last health check"""
        last_times = [
            check.get("last_check")
            for check in self.health_checks.values()
            if check.get("last_check")
        ]

        if last_times:
            return max(last_times)

        return None

    def check_all_health(self):
        """Perform health checks for all registered services"""
        results = []

        for name in self.health_checks.keys():
            result = self.check_health(name)
            if result:
                results.append(result)

        return results

    def _log_health_check(
        self, name, check_config, status_code, response_time, error_message=None
    ):
        """Log health check result to database"""
        try:
            conn = self._get_db_connection()
            if conn:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    INSERT INTO health_checks 
                    (domain_name, url, status_code, response_time, status, error_message, checked_at)
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                    (
                        name,
                        check_config["url"],
                        status_code,
                        response_time,
                        check_config["last_status"],
                        error_message,
                    ),
                )

                conn.commit()
                conn.close()

        except Exception as e:
            self.logger.error(f"Failed to log health check: {e}")

    def _get_db_connection(self):
        """Get database connection"""
        try:
            import sqlite3

            db_path = self.config.get("database_path")
            return sqlite3.connect(db_path, timeout=30.0)
        except Exception as e:
            self.logger.error(f"Database connection failed: {e}")
            return None
