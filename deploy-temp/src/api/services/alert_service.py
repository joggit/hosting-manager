# src/api/services/alert_service.py - Alert generation service
import psutil
from datetime import datetime


class AlertService:
    """Service for generating system alerts"""

    def __init__(self, deps):
        self.hosting_manager = deps["hosting_manager"]
        self.process_monitor = deps["process_monitor"]
        self.health_checker = deps["health_checker"]
        self.logger = deps["logger"]

    def generate_alerts(self):
        """Generate system alerts based on current status"""
        alerts = []

        try:
            # System resource alerts
            alerts.extend(self._check_system_resources())

            # Application alerts
            alerts.extend(self._check_applications())

            # Infrastructure alerts
            alerts.extend(self._check_infrastructure())

        except Exception as e:
            alerts.append(
                {
                    "id": "monitoring_error",
                    "severity": "warning",
                    "title": "Monitoring System Error",
                    "message": f"Error generating alerts: {str(e)}",
                    "timestamp": datetime.now().isoformat(),
                    "category": "system",
                }
            )

        return alerts

    def _check_system_resources(self):
        """Check system resource usage"""
        alerts = []

        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        # CPU alerts
        if cpu_usage > 90:
            alerts.append(
                {
                    "id": "cpu_critical",
                    "severity": "critical",
                    "title": "High CPU Usage",
                    "message": f"CPU usage is {cpu_usage:.1f}%",
                    "timestamp": datetime.now().isoformat(),
                    "category": "system",
                }
            )
        elif cpu_usage > 80:
            alerts.append(
                {
                    "id": "cpu_warning",
                    "severity": "warning",
                    "title": "Elevated CPU Usage",
                    "message": f"CPU usage is {cpu_usage:.1f}%",
                    "timestamp": datetime.now().isoformat(),
                    "category": "system",
                }
            )

        # Memory alerts
        if memory.percent > 90:
            alerts.append(
                {
                    "id": "memory_critical",
                    "severity": "critical",
                    "title": "High Memory Usage",
                    "message": f"Memory usage is {memory.percent:.1f}%",
                    "timestamp": datetime.now().isoformat(),
                    "category": "system",
                }
            )

        # Disk alerts
        if disk.percent > 95:
            alerts.append(
                {
                    "id": "disk_critical",
                    "severity": "critical",
                    "title": "Disk Space Critical",
                    "message": f"Disk usage is {disk.percent:.1f}%",
                    "timestamp": datetime.now().isoformat(),
                    "category": "system",
                }
            )

        return alerts

    def _check_applications(self):
        """Check application health"""
        alerts = []

        processes = self.process_monitor.get_all_processes()
        for process in processes:
            # Process down
            if process["status"] != "online":
                alerts.append(
                    {
                        "id": f"app_{process['name']}_down",
                        "severity": "critical",
                        "title": f"Application Down",
                        "message": f"{process['name']} is {process['status']}",
                        "timestamp": datetime.now().isoformat(),
                        "category": "application",
                        "app_name": process["name"],
                    }
                )

            # High restart count
            if process.get("restart_count", 0) > 5:
                alerts.append(
                    {
                        "id": f"app_{process['name']}_restarts",
                        "severity": "warning",
                        "title": f"High Restart Count",
                        "message": f"{process['name']} has restarted {process['restart_count']} times",
                        "timestamp": datetime.now().isoformat(),
                        "category": "application",
                        "app_name": process["name"],
                    }
                )

        return alerts

    def _check_infrastructure(self):
        """Check infrastructure components"""
        alerts = []

        # Nginx status
        if not self.hosting_manager._check_service_status("nginx"):
            alerts.append(
                {
                    "id": "nginx_down",
                    "severity": "critical",
                    "title": "Nginx Service Down",
                    "message": "Nginx web server is not running",
                    "timestamp": datetime.now().isoformat(),
                    "category": "infrastructure",
                }
            )

        # PM2 daemon (if available)
        if self.process_monitor.pm2_available and not self._check_pm2_daemon():
            alerts.append(
                {
                    "id": "pm2_daemon_down",
                    "severity": "warning",
                    "title": "PM2 Daemon Not Responding",
                    "message": "PM2 process manager daemon is not responding",
                    "timestamp": datetime.now().isoformat(),
                    "category": "infrastructure",
                }
            )

        return alerts

    def _check_pm2_daemon(self):
        """Check if PM2 daemon is responding"""
        try:
            import subprocess

            result = subprocess.run(["pm2", "ping"], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
