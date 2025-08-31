# src/api/server.py
"""
Flask API server with comprehensive process monitoring and PM2 support
Added PM2 status endpoint
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import os
import json
import time
import shutil
from datetime import datetime


class HostingAPI:
    """Enhanced API server with monitoring and PM2 support"""

    def __init__(
        self, hosting_manager, process_monitor, health_checker, config, logger
    ):
        self.hosting_manager = hosting_manager
        self.process_monitor = process_monitor
        self.health_checker = health_checker
        self.config = config
        self.logger = logger

        self.app = Flask(__name__)
        CORS(self.app)

        # Setup error handlers
        self.setup_error_handlers()
        self.setup_routes()

        # Log all registered routes
        self.logger.info("API routes registered:")
        for rule in self.app.url_map.iter_rules():
            self.logger.info(f"  {list(rule.methods)} {rule.rule}")

    def setup_error_handlers(self):
        """Setup error handlers"""

        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({"success": False, "error": "Endpoint not found"}), 404

        @self.app.errorhandler(500)
        def internal_error(error):
            return jsonify({"success": False, "error": "Internal server error"}), 500

    def setup_routes(self):
        """Setup all API routes"""

        @self.app.route("/api/health", methods=["GET"])
        def health_check():
            """Health check endpoint"""
            return jsonify(
                {
                    "status": "healthy",
                    "timestamp": datetime.now().isoformat(),
                    "version": "3.0.0",
                    "service": "Hosting Manager API with Enhanced Monitoring",
                    "readonly_filesystem": self.hosting_manager.readonly_filesystem,
                    "pm2_available": self.process_monitor.pm2_available,
                    "monitoring_active": self.process_monitor.is_monitoring_active(),
                }
            )

        @self.app.route("/api/status", methods=["GET"])
        def get_system_status():
            """Get comprehensive system status"""
            try:
                status = self.hosting_manager.get_system_status()

                # Add monitoring data
                status.update(
                    {
                        "monitoring": {
                            "process_monitor_active": self.process_monitor.is_monitoring_active(),
                            "health_checker_active": self.health_checker.is_active(),
                            "pm2_available": self.process_monitor.pm2_available,
                            "last_health_check": self.health_checker.get_last_check_time(),
                        },
                        "performance": self.process_monitor.get_system_performance(),
                    }
                )

                return jsonify({"success": True, "status": status})

            except Exception as e:
                self.logger.error(f"Status check failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/processes", methods=["GET"])
        def get_all_processes():
            """Get all managed processes with enhanced monitoring data"""
            try:
                self.logger.debug("API /api/processes called")

                # Get processes from monitor
                processes = self.process_monitor.get_all_processes()

                # Get summary statistics
                summary = self.process_monitor.get_process_summary()

                return jsonify(
                    {
                        "success": True,
                        "timestamp": datetime.now().isoformat(),
                        "summary": summary,
                        "processes": processes,
                        "monitoring": {
                            "pm2_available": self.process_monitor.pm2_available,
                            "total_memory": summary.get("total_memory_mb", 0),
                            "average_cpu": summary.get("average_cpu", 0.0),
                        },
                    }
                )

            except Exception as e:
                self.logger.error(f"Failed to get processes: {e}")
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": str(e),
                            "timestamp": datetime.now().isoformat(),
                        }
                    ),
                    500,
                )

        @self.app.route("/api/processes/<process_name>", methods=["GET"])
        def get_process_details(process_name):
            """Get detailed information about a specific process"""
            try:
                process_info = self.process_monitor.get_process_details(process_name)

                if process_info:
                    # Add health check data
                    health_data = self.health_checker.get_process_health(process_name)
                    process_info["health"] = health_data

                    return jsonify({"success": True, "process": process_info})
                else:
                    return (
                        jsonify({"success": False, "error": "Process not found"}),
                        404,
                    )

            except Exception as e:
                self.logger.error(f"Failed to get process details: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/deploy/nodejs", methods=["POST"])
        def deploy_nodejs_app():
            """Deploy Node.js application with PM2 support"""
            try:
                data = request.json

                if not data or not data.get("name") or not data.get("files"):
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": "Missing required fields: name, files",
                            }
                        ),
                        400,
                    )

                site_name = data["name"]
                project_files = data["files"]
                deploy_config = data.get("deployConfig", {})

                self.logger.info(f"Starting deployment for {site_name}")

                # Deploy using process monitor
                result = self.process_monitor.deploy_nodejs_app(
                    site_name, project_files, deploy_config
                )

                if result["success"]:
                    # Setup health monitoring for the new app
                    app_port = deploy_config.get("port", 3000)
                    self.health_checker.add_health_check(
                        site_name, f"http://localhost:{app_port}"
                    )

                return jsonify(result)

            except Exception as e:
                self.logger.error(f"Deployment failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/processes/<process_name>/start", methods=["POST"])
        def start_process(process_name):
            """Start a specific process"""
            try:
                success = self.process_monitor.start_process(process_name)

                if success:
                    return jsonify(
                        {"success": True, "message": f"Process {process_name} started"}
                    )
                else:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": f"Failed to start process {process_name}",
                            }
                        ),
                        500,
                    )

            except Exception as e:
                self.logger.error(f"Failed to start process: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/processes/<process_name>/stop", methods=["POST"])
        def stop_process(process_name):
            """Stop a specific process"""
            try:
                success = self.process_monitor.stop_process(process_name)

                if success:
                    return jsonify(
                        {"success": True, "message": f"Process {process_name} stopped"}
                    )
                else:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": f"Failed to stop process {process_name}",
                            }
                        ),
                        500,
                    )

            except Exception as e:
                self.logger.error(f"Failed to stop process: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/processes/<process_name>/restart", methods=["POST"])
        def restart_process(process_name):
            """Restart a specific process"""
            try:
                success = self.process_monitor.restart_process(process_name)

                if success:
                    return jsonify(
                        {
                            "success": True,
                            "message": f"Process {process_name} restarted",
                        }
                    )
                else:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": f"Failed to restart process {process_name}",
                            }
                        ),
                        500,
                    )

            except Exception as e:
                self.logger.error(f"Failed to restart process: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/processes/<process_name>/logs", methods=["GET"])
        def get_process_logs(process_name):
            """Get logs for a specific process"""
            try:
                lines = int(request.args.get("lines", 50))
                logs = self.process_monitor.get_process_logs(process_name, lines)

                return jsonify(
                    {
                        "success": True,
                        "logs": logs,
                        "process_name": process_name,
                        "lines_requested": lines,
                    }
                )

            except Exception as e:
                self.logger.error(f"Failed to get process logs: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/domains", methods=["GET"])
        def list_domains():
            """List all domains"""
            try:
                domains = self.hosting_manager.list_domains()

                # Add monitoring data to each domain
                for domain in domains:
                    domain_name = domain["domain_name"]
                    health = self.health_checker.get_domain_health(domain_name)
                    domain["health"] = health

                return jsonify(
                    {"success": True, "domains": domains, "count": len(domains)}
                )

            except Exception as e:
                self.logger.error(f"Failed to list domains: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/domains", methods=["POST"])
        def deploy_domain():
            """Deploy a new domain"""
            try:
                data = request.get_json()

                required_fields = ["domain_name", "port", "site_type"]
                if not data or not all(field in data for field in required_fields):
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": f"Missing required fields: {required_fields}",
                            }
                        ),
                        400,
                    )

                domain_name = data["domain_name"]
                port = int(data["port"])
                site_type = data["site_type"]

                if not 1 <= port <= 65535:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": "Port must be between 1 and 65535",
                            }
                        ),
                        400,
                    )

                if site_type not in ["static", "api", "node", "app"]:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": "site_type must be one of: static, api, node, app",
                            }
                        ),
                        400,
                    )

                success = self.hosting_manager.deploy_domain(
                    domain_name, port, site_type
                )

                if success:
                    # Setup health monitoring
                    if site_type != "static":
                        self.health_checker.add_health_check(
                            domain_name, f"http://localhost:{port}"
                        )

                    return jsonify(
                        {
                            "success": True,
                            "message": f"Domain {domain_name} deployed successfully",
                            "domain": {
                                "domain_name": domain_name,
                                "port": port,
                                "site_type": site_type,
                                "url": f"http://{domain_name}",
                                "monitoring_enabled": True,
                            },
                        }
                    )
                else:
                    return (
                        jsonify(
                            {"success": False, "error": "Domain deployment failed"}
                        ),
                        500,
                    )

            except Exception as e:
                self.logger.error(f"Domain deployment failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/domains/<domain_name>", methods=["DELETE"])
        def remove_domain(domain_name):
            """Remove a domain"""
            try:
                # Remove health checks
                self.health_checker.remove_health_check(domain_name)

                # Remove domain
                success = self.hosting_manager.remove_domain(domain_name)

                if success:
                    return jsonify(
                        {
                            "success": True,
                            "message": f"Domain {domain_name} removed successfully",
                        }
                    )
                else:
                    return (
                        jsonify({"success": False, "error": "Domain removal failed"}),
                        500,
                    )

            except Exception as e:
                self.logger.error(f"Domain removal failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/monitoring/health", methods=["GET"])
        def get_health_status():
            """Get health status for all monitored services"""
            try:
                health_data = self.health_checker.get_all_health_data()

                return jsonify(
                    {
                        "success": True,
                        "timestamp": datetime.now().isoformat(),
                        "health_checks": health_data,
                        "summary": {
                            "total_checks": len(health_data),
                            "healthy_count": len(
                                [h for h in health_data if h["status"] == "healthy"]
                            ),
                            "unhealthy_count": len(
                                [h for h in health_data if h["status"] == "unhealthy"]
                            ),
                        },
                    }
                )

            except Exception as e:
                self.logger.error(f"Health status check failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/monitoring/metrics", methods=["GET"])
        def get_system_metrics():
            """Get system performance metrics"""
            try:
                metrics = self.process_monitor.get_system_metrics()

                return jsonify(
                    {
                        "success": True,
                        "timestamp": datetime.now().isoformat(),
                        "metrics": metrics,
                    }
                )

            except Exception as e:
                self.logger.error(f"Metrics collection failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/pm2/status", methods=["GET"])
        def get_pm2_status():
            """Get PM2 daemon status and information"""
            try:
                if not self.process_monitor.pm2_available:
                    return (
                        jsonify({"success": False, "error": "PM2 not available"}),
                        400,
                    )

                pm2_status = self.process_monitor.get_pm2_status()
                return jsonify({"success": True, "pm2_status": pm2_status})

            except Exception as e:
                self.logger.error(f"PM2 status check failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/pm2/list", methods=["GET"])
        def get_pm2_processes():
            """Get PM2 process list"""
            try:
                if not self.process_monitor.pm2_available:
                    return (
                        jsonify({"success": False, "error": "PM2 not available"}),
                        400,
                    )

                pm2_data = self.process_monitor.get_pm2_processes()

                return jsonify({"success": True, "processes": pm2_data})

            except Exception as e:
                self.logger.error(f"PM2 list failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/pm2/<process_name>/<action>", methods=["POST"])
        def pm2_process_action(process_name, action):
            """Perform PM2 actions on a process"""
            try:
                if not self.process_monitor.pm2_available:
                    return (
                        jsonify({"success": False, "error": "PM2 not available"}),
                        400,
                    )

                valid_actions = ["start", "stop", "restart", "reload", "delete"]
                if action not in valid_actions:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": f"Invalid action. Must be one of: {valid_actions}",
                            }
                        ),
                        400,
                    )

                success = self.process_monitor.pm2_action(process_name, action)

                if success:
                    return jsonify(
                        {
                            "success": True,
                            "message": f"PM2 {action} successful for {process_name}",
                        }
                    )
                else:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": f"PM2 {action} failed for {process_name}",
                            }
                        ),
                        500,
                    )

            except Exception as e:
                self.logger.error(f"PM2 action failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/logs", methods=["GET"])
        def get_deployment_logs():
            """Get deployment logs with filtering"""
            try:
                limit = request.args.get("limit", 100, type=int)
                domain_filter = request.args.get("domain")
                action_filter = request.args.get("action")

                conn = self.hosting_manager.get_database_connection()
                if not conn:
                    return (
                        jsonify(
                            {"success": False, "error": "Database connection failed"}
                        ),
                        500,
                    )

                cursor = conn.cursor()

                # Build query based on filters
                where_clauses = []
                params = []

                if domain_filter:
                    where_clauses.append("domain_name = ?")
                    params.append(domain_filter)

                if action_filter:
                    where_clauses.append("action = ?")
                    params.append(action_filter)

                where_sql = (
                    " WHERE " + " AND ".join(where_clauses) if where_clauses else ""
                )
                params.append(limit)

                cursor.execute(
                    f"""
                    SELECT domain_name, action, status, message, details, created_at
                    FROM deployment_logs 
                    {where_sql}
                    ORDER BY created_at DESC
                    LIMIT ?
                """,
                    params,
                )

                logs = []
                for row in cursor.fetchall():
                    logs.append(
                        {
                            "domain_name": row[0],
                            "action": row[1],
                            "status": row[2],
                            "message": row[3],
                            "details": row[4],
                            "created_at": row[5],
                        }
                    )

                conn.close()

                return jsonify(
                    {
                        "success": True,
                        "logs": logs,
                        "count": len(logs),
                        "filters": {
                            "domain": domain_filter,
                            "action": action_filter,
                            "limit": limit,
                        },
                    }
                )

            except Exception as e:
                self.logger.error(f"Failed to get logs: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/check-ports", methods=["POST"])
        def check_available_ports():
            """Check for available ports"""
            try:
                data = request.get_json() or {}
                start_port = data.get("startPort", 3001)
                count = data.get("count", 5)

                available_ports = []
                for port in range(start_port, start_port + 100):
                    if self._is_port_available(port):
                        available_ports.append(port)
                        if len(available_ports) >= count:
                            break

                return jsonify({"success": True, "availablePorts": available_ports})

            except Exception as e:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": str(e),
                            "availablePorts": list(range(3001, 3006)),  # Fallback
                        }
                    ),
                    500,
                )

    def _is_port_available(self, port):
        """Check if a port is available"""
        import socket

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(("localhost", port))
                return result != 0
        except:
            return False

    def run(self, host="0.0.0.0", port=5000, debug=False):
        """Start the API server"""
        self.logger.info(f"Starting Hosting Manager API v3.0 on http://{host}:{port}")
        self.logger.info(f"Running as: {self.hosting_manager.current_user}")

        # Start background monitoring
        try:
            self.process_monitor.start_background_monitoring()
            self.health_checker.start_background_checks()
        except Exception as e:
            self.logger.warning(f"Failed to start background monitoring: {e}")

        # Show API status
        status = self.hosting_manager.get_system_status()
        self.logger.info(
            f"System ready - {status['domain_count']} domains, {status['active_apps']} apps running"
        )

        try:
            self.app.run(
                host=host, port=port, debug=False, use_reloader=False, threaded=True
            )
        except Exception as e:
            self.logger.error(f"API server error: {e}")
            raise
