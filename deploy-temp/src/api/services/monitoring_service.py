# src/api/services/monitoring_service.py - Monitoring business logic
import os
import time
import psutil
from datetime import datetime


class MonitoringService:
    """Service for monitoring business logic"""

    def __init__(self, deps):
        self.hosting_manager = deps["hosting_manager"]
        self.process_monitor = deps["process_monitor"]
        self.health_checker = deps["health_checker"]
        self.config = deps["config"]
        self.logger = deps["logger"]

    def get_dashboard_data(self):
        """Get dashboard overview data"""
        return {
            "timestamp": datetime.now().isoformat(),
            "system": self._get_system_health(),
            "applications": self._get_all_app_health(),
            "infrastructure": self._get_infrastructure_status(),
            "performance": self._get_performance_metrics(),
            "summary": self._get_dashboard_summary(),
        }

    def get_all_sites_status(self):
        """Get status for all sites"""
        sites_data = []
        domains = self.hosting_manager.list_domains()
        processes = self.process_monitor.get_all_processes()

        for domain in domains:
            site_data = self._get_site_detailed_status(domain, processes)
            sites_data.append(site_data)

        return sites_data

    def get_site_detailed_status(self, site_name):
        """Get detailed status for a specific site"""
        return {
            "site_name": site_name,
            "timestamp": datetime.now().isoformat(),
            "health": self.health_checker.get_domain_health(site_name),
            "performance": self._get_site_performance(site_name),
            "process": self.process_monitor.get_process_details(site_name),
            "logs": self.process_monitor.get_process_logs(site_name, 50),
        }

    def get_system_resources(self):
        """Get system resource information"""
        try:
            return {
                "timestamp": datetime.now().isoformat(),
                "cpu": {
                    "usage_percent": psutil.cpu_percent(interval=1),
                    "count": psutil.cpu_count(),
                    "load_average": os.getloadavg(),
                    "per_core": psutil.cpu_percent(interval=1, percpu=True),
                },
                "memory": {
                    "total": psutil.virtual_memory().total,
                    "available": psutil.virtual_memory().available,
                    "used": psutil.virtual_memory().used,
                    "percentage": psutil.virtual_memory().percent,
                    "swap": {
                        "total": psutil.swap_memory().total,
                        "used": psutil.swap_memory().used,
                        "percentage": psutil.swap_memory().percent,
                    },
                },
                "disk": {
                    "total": psutil.disk_usage("/").total,
                    "used": psutil.disk_usage("/").used,
                    "free": psutil.disk_usage("/").free,
                    "percentage": psutil.disk_usage("/").percent,
                },
                "network": self._get_network_stats(),
                "processes": {
                    "total": len(psutil.pids()),
                    "running": len(
                        [p for p in psutil.process_iter() if p.status() == "running"]
                    ),
                    "sleeping": len(
                        [p for p in psutil.process_iter() if p.status() == "sleeping"]
                    ),
                },
            }
        except Exception as e:
            self.logger.error(f"System resources failed: {e}")
            return {"error": str(e)}

    # Helper methods
    def _get_system_health(self):
        try:
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            return {
                "status": (
                    "healthy"
                    if cpu_usage < 80 and memory.percent < 80 and disk.percent < 90
                    else "warning"
                ),
                "cpu_usage": cpu_usage,
                "memory_usage": memory.percent,
                "disk_usage": disk.percent,
                "load_average": os.getloadavg()[0],
                "uptime": time.time() - psutil.boot_time(),
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _get_all_app_health(self):
        # Implementation here...
        return []

    def _get_infrastructure_status(self):
        # Implementation here...
        return {}

    def _get_performance_metrics(self):
        # Implementation here...
        return {}

    def _get_dashboard_summary(self):
        # Implementation here...
        return {}

    def _get_site_detailed_status(self, domain, processes):
        # Implementation here...
        return {}

    def _get_site_performance(self, site_name):
        # Implementation here...
        return {}

    def _get_network_stats(self):
        try:
            net_io = psutil.net_io_counters()
            return {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv,
            }
        except:
            return {}
