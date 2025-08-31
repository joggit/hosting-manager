# src/api/nextjs_monitoring.py
"""
Next.js Multisite Monitoring API Extension
Provides comprehensive monitoring endpoints for React frontend
"""

from flask import request, jsonify
import subprocess
import json
import os
import time
import psutil
import glob
from datetime import datetime, timedelta


class NextJSMonitoringAPI:
    """Extended monitoring API specifically for Next.js multisite hosting"""

    def __init__(
        self, app, hosting_manager, process_monitor, health_checker, config, logger
    ):
        self.app = app
        self.hosting_manager = hosting_manager
        self.process_monitor = process_monitor
        self.health_checker = health_checker
        self.config = config
        self.logger = logger

        self.setup_nextjs_routes()

    def setup_nextjs_routes(self):
        """Setup Next.js specific monitoring routes"""

        @self.app.route("/api/monitoring/dashboard", methods=["GET"])
        def get_dashboard_overview():
            """Get complete dashboard overview for React frontend"""
            try:
                dashboard_data = {
                    "timestamp": datetime.now().isoformat(),
                    "system": self._get_system_health(),
                    "applications": self._get_all_app_health(),
                    "infrastructure": self._get_infrastructure_status(),
                    "alerts": self._get_active_alerts(),
                    "performance": self._get_performance_metrics(),
                    "summary": self._get_dashboard_summary(),
                }

                return jsonify(
                    {
                        "success": True,
                        "dashboard": dashboard_data,
                        "last_updated": datetime.now().isoformat(),
                    }
                )

            except Exception as e:
                self.logger.error(f"Dashboard overview failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/monitoring/sites", methods=["GET"])
        def get_all_sites_status():
            """Get comprehensive status for all Next.js sites"""
            try:
                sites_data = []

                # Get all domains and their associated processes
                domains = self.hosting_manager.list_domains()
                processes = self.process_monitor.get_all_processes()

                for domain in domains:
                    site_data = self._get_site_detailed_status(domain, processes)
                    sites_data.append(site_data)

                # Sort by status (unhealthy first, then by name)
                sites_data.sort(
                    key=lambda x: (x["overall_status"] != "healthy", x["domain_name"])
                )

                return jsonify(
                    {
                        "success": True,
                        "sites": sites_data,
                        "total_sites": len(sites_data),
                        "healthy_sites": len(
                            [s for s in sites_data if s["overall_status"] == "healthy"]
                        ),
                        "timestamp": datetime.now().isoformat(),
                    }
                )

            except Exception as e:
                self.logger.error(f"Sites status failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/monitoring/sites/<site_name>", methods=["GET"])
        def get_site_detailed_monitoring(site_name):
            """Get detailed monitoring data for a specific site"""
            try:
                site_data = {
                    "site_name": site_name,
                    "timestamp": datetime.now().isoformat(),
                    "health": self._get_site_health_details(site_name),
                    "performance": self._get_site_performance(site_name),
                    "process": self._get_site_process_info(site_name),
                    "nginx": self._get_site_nginx_status(site_name),
                    "ssl": self._get_site_ssl_status(site_name),
                    "logs": self._get_site_recent_logs(site_name),
                    "metrics_history": self._get_site_metrics_history(site_name),
                    "deployment": self._get_site_deployment_info(site_name),
                }

                return jsonify({"success": True, "site": site_data})

            except Exception as e:
                self.logger.error(f"Site detailed monitoring failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/monitoring/system/resources", methods=["GET"])
        def get_system_resources():
            """Get real-time system resource usage"""
            try:
                resources = {
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
                            [
                                p
                                for p in psutil.process_iter()
                                if p.status() == "running"
                            ]
                        ),
                        "sleeping": len(
                            [
                                p
                                for p in psutil.process_iter()
                                if p.status() == "sleeping"
                            ]
                        ),
                    },
                }

                return jsonify({"success": True, "resources": resources})

            except Exception as e:
                self.logger.error(f"System resources failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/monitoring/nginx", methods=["GET"])
        def get_nginx_status():
            """Get comprehensive nginx status"""
            try:
                nginx_data = {
                    "timestamp": datetime.now().isoformat(),
                    "service_status": self._get_nginx_service_status(),
                    "configuration": self._get_nginx_config_status(),
                    "sites": self._get_nginx_sites_status(),
                    "performance": self._get_nginx_performance(),
                    "logs": self._get_nginx_recent_logs(),
                }

                return jsonify({"success": True, "nginx": nginx_data})

            except Exception as e:
                self.logger.error(f"Nginx status failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/monitoring/pm2/detailed", methods=["GET"])
        def get_pm2_detailed_status():
            """Get detailed PM2 status including per-process metrics"""
            try:
                pm2_data = {
                    "timestamp": datetime.now().isoformat(),
                    "daemon": self.process_monitor.get_pm2_status(),
                    "processes": self._get_pm2_detailed_processes(),
                    "performance": self._get_pm2_performance_summary(),
                    "logs": self._get_pm2_recent_logs(),
                }

                return jsonify({"success": True, "pm2": pm2_data})

            except Exception as e:
                self.logger.error(f"PM2 detailed status failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/monitoring/alerts", methods=["GET"])
        def get_active_alerts():
            """Get all active system alerts and warnings"""
            try:
                alerts = self._generate_alerts()

                return jsonify(
                    {
                        "success": True,
                        "alerts": alerts,
                        "alert_count": len(alerts),
                        "critical_count": len(
                            [a for a in alerts if a["severity"] == "critical"]
                        ),
                        "warning_count": len(
                            [a for a in alerts if a["severity"] == "warning"]
                        ),
                        "timestamp": datetime.now().isoformat(),
                    }
                )

            except Exception as e:
                self.logger.error(f"Alerts retrieval failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/monitoring/deployment/status", methods=["GET"])
        def get_deployment_overview():
            """Get overview of all deployment statuses"""
            try:
                deployment_data = {
                    "timestamp": datetime.now().isoformat(),
                    "recent_deployments": self._get_recent_deployments(),
                    "deployment_stats": self._get_deployment_statistics(),
                    "failed_deployments": self._get_failed_deployments(),
                    "build_queue": self._get_build_queue_status(),
                }

                return jsonify({"success": True, "deployment": deployment_data})

            except Exception as e:
                self.logger.error(f"Deployment overview failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/monitoring/logs/stream/<site_name>", methods=["GET"])
        def stream_site_logs(site_name):
            """Stream real-time logs for a site"""
            try:
                lines = int(request.args.get("lines", 100))
                follow = request.args.get("follow", "false").lower() == "true"

                logs = self.process_monitor.get_process_logs(site_name, lines)

                if follow:
                    # For real-time streaming, you'd implement WebSocket here
                    # For now, return recent logs with streaming info
                    return jsonify(
                        {
                            "success": True,
                            "logs": logs,
                            "streaming": True,
                            "site_name": site_name,
                            "websocket_endpoint": f"/ws/logs/{site_name}",
                        }
                    )
                else:
                    return jsonify(
                        {
                            "success": True,
                            "logs": logs,
                            "site_name": site_name,
                            "timestamp": datetime.now().isoformat(),
                        }
                    )

            except Exception as e:
                self.logger.error(f"Log streaming failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

    def _get_system_health(self):
        """Get overall system health indicators"""
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
        """Get health status for all Next.js applications"""
        try:
            apps = []
            processes = self.process_monitor.get_all_processes()
            domains = self.hosting_manager.list_domains()

            for domain in domains:
                if domain.get("site_type") in ["node", "app"]:
                    domain_name = domain["domain_name"]

                    # Find associated process
                    app_process = next(
                        (p for p in processes if p["name"] == domain_name), None
                    )

                    # Get health check data
                    health_data = self.health_checker.get_domain_health(domain_name)

                    app_info = {
                        "name": domain_name,
                        "port": domain["port"],
                        "status": app_process["status"] if app_process else "unknown",
                        "health": health_data.get("status", "unknown"),
                        "memory": (
                            app_process.get("memory", "N/A") if app_process else "N/A"
                        ),
                        "cpu": app_process.get("cpu", "N/A") if app_process else "N/A",
                        "uptime": (
                            self._calculate_uptime(app_process) if app_process else None
                        ),
                        "restart_count": (
                            app_process.get("restart_count", 0) if app_process else 0
                        ),
                        "response_time": health_data.get("response_time"),
                        "last_health_check": health_data.get("last_check"),
                    }
                    apps.append(app_info)

            return apps
        except Exception as e:
            self.logger.error(f"App health check failed: {e}")
            return []

    def _get_infrastructure_status(self):
        """Get infrastructure component status"""
        return {
            "nginx": {
                "status": (
                    "running"
                    if self.hosting_manager._check_service_status("nginx")
                    else "stopped"
                ),
                "config_valid": self.hosting_manager._test_nginx_config(),
            },
            "pm2": {
                "available": self.process_monitor.pm2_available,
                "daemon_running": self._check_pm2_daemon(),
                "process_count": (
                    len(self.process_monitor.get_pm2_processes())
                    if self.process_monitor.pm2_available
                    else 0
                ),
            },
            "database": {
                "connected": self.hosting_manager.get_database_connection() is not None
            },
            "monitoring": {
                "process_monitor": self.process_monitor.is_monitoring_active(),
                "health_checker": self.health_checker.is_active(),
            },
        }

    def _get_active_alerts(self):
        """Get current active alerts"""
        return self._generate_alerts()

    def _get_performance_metrics(self):
        """Get key performance metrics"""
        try:
            processes = self.process_monitor.get_all_processes()

            return {
                "total_memory_usage": sum(
                    self._parse_memory(p.get("memory", "0MB")) for p in processes
                ),
                "average_cpu_usage": sum(
                    self._parse_cpu(p.get("cpu", "0%")) for p in processes
                )
                / max(len(processes), 1),
                "active_connections": self._get_active_connections(),
                "response_times": self._get_average_response_times(),
                "error_rates": self._get_error_rates(),
            }
        except Exception as e:
            return {"error": str(e)}

    def _get_dashboard_summary(self):
        """Get dashboard summary statistics"""
        try:
            domains = self.hosting_manager.list_domains()
            processes = self.process_monitor.get_all_processes()

            total_sites = len(
                [d for d in domains if d.get("site_type") in ["node", "app"]]
            )
            healthy_sites = len(
                [
                    d
                    for d in domains
                    if self.health_checker.get_domain_health(d["domain_name"]).get(
                        "status"
                    )
                    == "healthy"
                ]
            )

            return {
                "total_sites": total_sites,
                "healthy_sites": healthy_sites,
                "unhealthy_sites": total_sites - healthy_sites,
                "total_processes": len(processes),
                "running_processes": len(
                    [p for p in processes if p["status"] == "online"]
                ),
                "system_health": (
                    "healthy"
                    if psutil.cpu_percent() < 80
                    and psutil.virtual_memory().percent < 80
                    else "warning"
                ),
            }
        except Exception as e:
            return {"error": str(e)}

    def _get_site_detailed_status(self, domain, processes):
        """Get detailed status for a single site"""
        domain_name = domain["domain_name"]

        # Find associated process
        site_process = next((p for p in processes if p["name"] == domain_name), None)

        # Get health data
        health_data = self.health_checker.get_domain_health(domain_name)

        # Determine overall status
        process_status = site_process["status"] if site_process else "unknown"
        health_status = health_data.get("status", "unknown")

        if process_status == "online" and health_status == "healthy":
            overall_status = "healthy"
        elif process_status == "online" and health_status != "healthy":
            overall_status = "degraded"
        else:
            overall_status = "unhealthy"

        return {
            "domain_name": domain_name,
            "port": domain["port"],
            "site_type": domain["site_type"],
            "overall_status": overall_status,
            "process": {
                "status": process_status,
                "pid": site_process.get("pid") if site_process else None,
                "memory": site_process.get("memory", "N/A") if site_process else "N/A",
                "cpu": site_process.get("cpu", "N/A") if site_process else "N/A",
                "restart_count": (
                    site_process.get("restart_count", 0) if site_process else 0
                ),
                "process_manager": (
                    site_process.get("process_manager", "unknown")
                    if site_process
                    else "unknown"
                ),
            },
            "health": {
                "status": health_status,
                "response_time": health_data.get("response_time"),
                "last_check": health_data.get("last_check"),
                "consecutive_failures": health_data.get("consecutive_failures", 0),
                "uptime_percentage": health_data.get("uptime_percentage", 0),
            },
            "ssl_enabled": domain.get("ssl_enabled", False),
            "created_at": domain.get("created_at"),
            "url": f"http://{domain_name}",
        }

    def _generate_alerts(self):
        """Generate system alerts based on current status"""
        alerts = []

        try:
            # System resource alerts
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

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

            # Application alerts
            processes = self.process_monitor.get_all_processes()
            for process in processes:
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

            # Infrastructure alerts
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

    def _check_pm2_daemon(self):
        """Check if PM2 daemon is responding"""
        try:
            result = subprocess.run(["pm2", "ping"], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def _parse_memory(self, memory_str):
        """Parse memory string to MB"""
        try:
            if "MB" in str(memory_str):
                return int(str(memory_str).replace("MB", ""))
            elif "GB" in str(memory_str):
                return int(float(str(memory_str).replace("GB", "")) * 1024)
        except:
            pass
        return 0

    def _parse_cpu(self, cpu_str):
        """Parse CPU string to percentage"""
        try:
            if "%" in str(cpu_str):
                return float(str(cpu_str).replace("%", ""))
        except:
            pass
        return 0.0

    def _calculate_uptime(self, process):
        """Calculate process uptime"""
        try:
            if process.get("pid"):
                proc = psutil.Process(process["pid"])
                create_time = datetime.fromtimestamp(proc.create_time())
                uptime = datetime.now() - create_time
                return {
                    "seconds": int(uptime.total_seconds()),
                    "human_readable": str(uptime).split(".")[0],
                }
        except:
            pass
        return None

    def _get_network_stats(self):
        """Get network statistics"""
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

    def _get_active_connections(self):
        """Get active network connections count"""
        try:
            connections = psutil.net_connections()
            return len([c for c in connections if c.status == "ESTABLISHED"])
        except:
            return 0

    def _get_average_response_times(self):
        """Get average response times from health checks"""
        try:
            health_data = self.health_checker.get_all_health_data()
            response_times = [
                h.get("response_time", 0) for h in health_data if h.get("response_time")
            ]
            return sum(response_times) / len(response_times) if response_times else 0
        except:
            return 0

    def _get_error_rates(self):
        """Calculate error rates from health checks"""
        try:
            health_data = self.health_checker.get_all_health_data()
            if not health_data:
                return 0

            unhealthy_count = len([h for h in health_data if h["status"] != "healthy"])
            return (unhealthy_count / len(health_data)) * 100
        except:
            return 0

    # Additional helper methods for detailed site monitoring
    def _get_site_health_details(self, site_name):
        """Get detailed health information for a site"""
        return self.health_checker.get_domain_health(site_name)

    def _get_site_performance(self, site_name):
        """Get performance metrics for a site"""
        # This would integrate with your performance monitoring
        return {"response_time": 0, "throughput": 0, "error_rate": 0}

    def _get_site_process_info(self, site_name):
        """Get process information for a site"""
        return self.process_monitor.get_process_details(site_name)

    def _get_site_nginx_status(self, site_name):
        """Get nginx configuration status for a site"""
        return {"config_exists": True, "config_valid": True}

    def _get_site_ssl_status(self, site_name):
        """Get SSL certificate status for a site"""
        return {"enabled": False, "valid": False, "expires": None}

    def _get_site_recent_logs(self, site_name):
        """Get recent logs for a site"""
        return self.process_monitor.get_process_logs(site_name, 50)

    def _get_site_metrics_history(self, site_name):
        """Get historical metrics for a site"""
        return {"cpu_history": [], "memory_history": [], "response_time_history": []}

    def _get_site_deployment_info(self, site_name):
        """Get deployment information for a site"""
        return {"last_deployment": None, "version": None, "build_status": "unknown"}

    # Additional helper methods would go here...
    def _get_nginx_service_status(self):
        return {"running": self.hosting_manager._check_service_status("nginx")}

    def _get_nginx_config_status(self):
        return {"valid": self.hosting_manager._test_nginx_config()}

    def _get_nginx_sites_status(self):
        return {"enabled_sites": [], "available_sites": []}

    def _get_nginx_performance(self):
        return {"requests_per_second": 0, "connections": 0}

    def _get_nginx_recent_logs(self):
        return []

    def _get_pm2_detailed_processes(self):
        return self.process_monitor.get_pm2_processes()

    def _get_pm2_performance_summary(self):
        return {"total_memory": 0, "total_cpu": 0}

    def _get_pm2_recent_logs(self):
        return []

    def _get_recent_deployments(self):
        return []

    def _get_deployment_statistics(self):
        return {"successful": 0, "failed": 0, "in_progress": 0}

    def _get_failed_deployments(self):
        return []

    def _get_build_queue_status(self):
        return {"queued": 0, "building": 0}
