# src/api/server.py
"""
Flask API server with comprehensive process monitoring, PM2 support, and detailed nginx site information
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import os
import json
import time
import shutil
import socket
import glob
import re
from pathlib import Path
from datetime import datetime


class HostingAPI:
    """Enhanced API server with monitoring, PM2 support, and comprehensive nginx site information"""

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
        self.setup_nginx_info_routes()  # Add enhanced nginx routes

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
        """Setup all standard API routes"""

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
                        "performance": (
                            self.process_monitor.get_system_performance()
                            if hasattr(self.process_monitor, "get_system_performance")
                            else {}
                        ),
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

        # Include all other existing routes from the original file...
        # (I'll include the key ones for brevity)

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

    def setup_nginx_info_routes(self):
        """Setup enhanced nginx site information routes"""

        @self.app.route("/api/sites", methods=["GET"])
        def get_all_sites_detailed():
            """Get comprehensive information about all hosted sites"""
            try:
                sites_info = self._get_comprehensive_sites_info()

                return jsonify(
                    {
                        "success": True,
                        "timestamp": datetime.now().isoformat(),
                        "server_info": self._get_server_info(),
                        "sites": sites_info,
                        "summary": {
                            "total_sites": len(sites_info),
                            "active_sites": len(
                                [s for s in sites_info if s["status"] == "active"]
                            ),
                            "ssl_enabled_sites": len(
                                [s for s in sites_info if s.get("ssl_enabled", False)]
                            ),
                            "static_sites": len(
                                [
                                    s
                                    for s in sites_info
                                    if s.get("site_type") == "static"
                                ]
                            ),
                            "dynamic_sites": len(
                                [
                                    s
                                    for s in sites_info
                                    if s.get("site_type") != "static"
                                ]
                            ),
                        },
                    }
                )

            except Exception as e:
                self.logger.error(f"Failed to get sites info: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/sites/<domain_name>/details", methods=["GET"])
        def get_site_details(domain_name):
            """Get detailed information about a specific site"""
            try:
                site_info = self._get_site_detailed_info(domain_name)

                if not site_info:
                    return jsonify({"success": False, "error": "Site not found"}), 404

                return jsonify(
                    {
                        "success": True,
                        "timestamp": datetime.now().isoformat(),
                        "site": site_info,
                    }
                )

            except Exception as e:
                self.logger.error(f"Failed to get site details: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/nginx/status", methods=["GET"])
        def get_nginx_status():
            """Get comprehensive nginx status and configuration"""
            try:
                nginx_info = self._get_nginx_comprehensive_status()

                return jsonify(
                    {
                        "success": True,
                        "timestamp": datetime.now().isoformat(),
                        "nginx": nginx_info,
                    }
                )

            except Exception as e:
                self.logger.error(f"Failed to get nginx status: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/nginx/sites-enabled", methods=["GET"])
        def get_nginx_enabled_sites():
            """Get all nginx enabled sites with their configurations"""
            try:
                enabled_sites = self._get_nginx_enabled_sites()

                return jsonify(
                    {
                        "success": True,
                        "timestamp": datetime.now().isoformat(),
                        "enabled_sites": enabled_sites,
                        "count": len(enabled_sites),
                    }
                )

            except Exception as e:
                self.logger.error(f"Failed to get nginx enabled sites: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/sites/connectivity", methods=["GET"])
        def test_sites_connectivity():
            """Test connectivity to all hosted sites"""
            try:
                connectivity_results = self._test_all_sites_connectivity()

                return jsonify(
                    {
                        "success": True,
                        "timestamp": datetime.now().isoformat(),
                        "connectivity_tests": connectivity_results,
                        "summary": {
                            "total_tested": len(connectivity_results),
                            "responding": len(
                                [r for r in connectivity_results if r["responding"]]
                            ),
                            "not_responding": len(
                                [r for r in connectivity_results if not r["responding"]]
                            ),
                        },
                    }
                )

            except Exception as e:
                self.logger.error(f"Failed to test connectivity: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/server/network-info", methods=["GET"])
        def get_server_network_info():
            """Get comprehensive server network information"""
            try:
                network_info = self._get_comprehensive_network_info()

                return jsonify(
                    {
                        "success": True,
                        "timestamp": datetime.now().isoformat(),
                        "network": network_info,
                    }
                )

            except Exception as e:
                self.logger.error(f"Failed to get network info: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/sites/<domain_name>/nginx-config", methods=["GET"])
        def get_site_nginx_config(domain_name):
            """Get nginx configuration for a specific site"""
            try:
                config_content = self._get_nginx_config_content(domain_name)
                config_info = self._get_nginx_config_info(domain_name)

                if not config_content:
                    return (
                        jsonify({"success": False, "error": "Nginx config not found"}),
                        404,
                    )

                return jsonify(
                    {
                        "success": True,
                        "domain_name": domain_name,
                        "config_info": config_info,
                        "config_content": config_content,
                        "parsed_config": self._parse_nginx_config_content(
                            config_content
                        ),
                    }
                )

            except Exception as e:
                self.logger.error(f"Failed to get nginx config: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

    # Enhanced nginx information helper methods
    def _get_comprehensive_sites_info(self):
        """Get comprehensive information about all sites"""
        sites_info = []

        try:
            # Get sites from database
            conn = self.hosting_manager.get_database_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT domain_name, port, site_type, ssl_enabled, status, created_at, updated_at
                    FROM domains 
                    WHERE status = 'active'
                    ORDER BY created_at DESC
                """
                )

                db_sites = cursor.fetchall()
                conn.close()

                for row in db_sites:
                    (
                        domain_name,
                        port,
                        site_type,
                        ssl_enabled,
                        status,
                        created_at,
                        updated_at,
                    ) = row

                    site_info = {
                        "domain_name": domain_name,
                        "port": port,
                        "site_type": site_type,
                        "ssl_enabled": bool(ssl_enabled),
                        "status": status,
                        "created_at": created_at,
                        "updated_at": updated_at,
                        "urls": self._generate_site_urls(
                            domain_name, bool(ssl_enabled)
                        ),
                        "nginx_config": self._get_nginx_config_info(domain_name),
                        "directory_info": self._get_site_directory_info(domain_name),
                        "health": self.health_checker.get_domain_health(domain_name),
                        "connectivity": self._test_site_connectivity(domain_name, port),
                    }

                    # Add process information if it's a dynamic site
                    if site_type != "static":
                        process_info = self._get_site_process_info(domain_name)
                        site_info["process"] = process_info

                    sites_info.append(site_info)

            # Also check for nginx sites that might not be in database
            nginx_sites = self._get_nginx_only_sites()
            sites_info.extend(nginx_sites)

        except Exception as e:
            self.logger.error(f"Failed to get comprehensive sites info: {e}")

        return sites_info

    def _get_site_detailed_info(self, domain_name):
        """Get detailed information about a specific site"""
        try:
            # Get from database first
            conn = self.hosting_manager.get_database_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT domain_name, port, site_type, ssl_enabled, status, created_at, updated_at
                    FROM domains 
                    WHERE domain_name = ?
                """,
                    (domain_name,),
                )

                row = cursor.fetchone()
                conn.close()

                if row:
                    (
                        domain_name,
                        port,
                        site_type,
                        ssl_enabled,
                        status,
                        created_at,
                        updated_at,
                    ) = row

                    detailed_info = {
                        "basic_info": {
                            "domain_name": domain_name,
                            "port": port,
                            "site_type": site_type,
                            "ssl_enabled": bool(ssl_enabled),
                            "status": status,
                            "created_at": created_at,
                            "updated_at": updated_at,
                        },
                        "urls": self._generate_site_urls(
                            domain_name, bool(ssl_enabled)
                        ),
                        "nginx": {
                            "config_file": f"/etc/nginx/sites-available/{domain_name}",
                            "enabled_link": f"/etc/nginx/sites-enabled/{domain_name}",
                            "config_content": self._get_nginx_config_content(
                                domain_name
                            ),
                            "config_test": self._test_nginx_config_for_site(
                                domain_name
                            ),
                        },
                        "directory": self._get_detailed_directory_info(domain_name),
                        "health": self.health_checker.get_domain_health(domain_name),
                        "connectivity": self._detailed_connectivity_test(
                            domain_name, port
                        ),
                        "logs": self._get_site_logs(domain_name),
                        "performance": self._get_site_performance_info(
                            domain_name, port
                        ),
                    }

                    # Add process information for dynamic sites
                    if site_type != "static":
                        detailed_info["process"] = self._get_detailed_process_info(
                            domain_name
                        )

                    return detailed_info

        except Exception as e:
            self.logger.error(
                f"Failed to get detailed site info for {domain_name}: {e}"
            )

        return None

    def _get_server_info(self):
        """Get server information"""
        try:
            hostname = socket.gethostname()

            # Get primary IP address
            try:
                # Connect to a remote address to determine local IP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                primary_ip = s.getsockname()[0]
                s.close()
            except:
                primary_ip = "127.0.0.1"

            return {
                "hostname": hostname,
                "primary_ip": primary_ip,
                "all_ips": self._get_all_server_ips(),
                "os_info": self._get_os_info(),
                "nginx_version": self._get_nginx_version(),
            }

        except Exception as e:
            self.logger.error(f"Failed to get server info: {e}")
            return {}

    def _get_all_server_ips(self):
        """Get all IP addresses of the server"""
        try:
            # Try using netifaces if available
            try:
                import netifaces

                ips = []
                for interface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            ip = addr["addr"]
                            if ip != "127.0.0.1":
                                ips.append(
                                    {
                                        "interface": interface,
                                        "ip": ip,
                                        "netmask": addr.get("netmask", ""),
                                    }
                                )
                return ips
            except ImportError:
                pass

            # Fallback method using hostname
            try:
                hostname = socket.gethostname()
                ip_list = socket.gethostbyname_ex(hostname)[2]
                return [
                    {"interface": "unknown", "ip": ip, "netmask": ""}
                    for ip in ip_list
                    if not ip.startswith("127.")
                ]
            except:
                return [{"interface": "lo", "ip": "127.0.0.1", "netmask": "255.0.0.0"}]

        except Exception as e:
            self.logger.error(f"Failed to get server IPs: {e}")
            return []

    def _generate_site_urls(self, domain_name, ssl_enabled):
        """Generate URLs for a site"""
        urls = {"http": f"http://{domain_name}", "primary": f"http://{domain_name}"}

        if ssl_enabled:
            urls["https"] = f"https://{domain_name}"
            urls["primary"] = f"https://{domain_name}"

        # Add server IP URLs
        server_info = self._get_server_info()
        if server_info.get("primary_ip"):
            urls["ip_http"] = f"http://{server_info['primary_ip']}"
            if ssl_enabled:
                urls["ip_https"] = f"https://{server_info['primary_ip']}"

        return urls

    def _get_nginx_config_info(self, domain_name):
        """Get nginx configuration information for a site"""
        try:
            config_file = f"/etc/nginx/sites-available/{domain_name}"
            enabled_file = f"/etc/nginx/sites-enabled/{domain_name}"

            return {
                "config_exists": os.path.exists(config_file),
                "enabled": os.path.exists(enabled_file),
                "config_file": config_file,
                "enabled_file": enabled_file,
                "last_modified": self._get_file_modification_time(config_file),
            }

        except Exception as e:
            self.logger.error(f"Failed to get nginx config info for {domain_name}: {e}")
            return {}

    def _get_nginx_config_content(self, domain_name):
        """Get nginx configuration file content"""
        try:
            config_file = f"/etc/nginx/sites-available/{domain_name}"
            if os.path.exists(config_file):
                with open(config_file, "r") as f:
                    return f.read()
        except Exception as e:
            self.logger.error(f"Failed to read nginx config for {domain_name}: {e}")
        return None

    def _get_site_directory_info(self, domain_name):
        """Get site directory information"""
        try:
            site_path = f"{self.config.get('web_root')}/{domain_name}"

            if os.path.exists(site_path):
                # Get directory size
                total_size = 0
                file_count = 0

                for dirpath, dirnames, filenames in os.walk(site_path):
                    for filename in filenames:
                        filepath = os.path.join(dirpath, filename)
                        try:
                            total_size += os.path.getsize(filepath)
                            file_count += 1
                        except OSError:
                            pass

                return {
                    "path": site_path,
                    "exists": True,
                    "total_size_bytes": total_size,
                    "total_size_mb": round(total_size / (1024 * 1024), 2),
                    "file_count": file_count,
                    "last_modified": self._get_file_modification_time(site_path),
                    "permissions": oct(os.stat(site_path).st_mode)[-3:],
                }
            else:
                return {"path": site_path, "exists": False}

        except Exception as e:
            self.logger.error(f"Failed to get directory info for {domain_name}: {e}")
            return {}

    def _test_site_connectivity(self, domain_name, port):
        """Test basic connectivity to a site"""
        try:
            import requests

            urls_to_test = [
                f"http://{domain_name}",
                f"http://localhost:{port}" if port else None,
            ]

            results = []
            for url in urls_to_test:
                if url:
                    try:
                        response = requests.get(url, timeout=5, allow_redirects=True)
                        results.append(
                            {
                                "url": url,
                                "status_code": response.status_code,
                                "responding": 200 <= response.status_code < 400,
                                "response_time_ms": round(
                                    response.elapsed.total_seconds() * 1000, 2
                                ),
                            }
                        )
                    except requests.exceptions.RequestException as e:
                        results.append(
                            {
                                "url": url,
                                "status_code": None,
                                "responding": False,
                                "error": str(e),
                            }
                        )

            return results

        except Exception as e:
            self.logger.error(f"Failed to test connectivity for {domain_name}: {e}")
            return []

    def _get_nginx_comprehensive_status(self):
        """Get comprehensive nginx status"""
        try:
            # Check if nginx is running
            nginx_running = self.hosting_manager._check_service_status("nginx")

            # Get nginx version
            nginx_version = self._get_nginx_version()

            # Get nginx configuration test
            config_test = self.hosting_manager._test_nginx_config()

            # Count sites
            sites_available = len(glob.glob("/etc/nginx/sites-available/*"))
            sites_enabled = len(glob.glob("/etc/nginx/sites-enabled/*"))

            # Get nginx processes
            nginx_processes = self._get_nginx_processes()

            return {
                "running": nginx_running,
                "version": nginx_version,
                "config_test_passed": config_test,
                "sites_available": sites_available,
                "sites_enabled": sites_enabled,
                "processes": nginx_processes,
                "config_files": {
                    "main_config": "/etc/nginx/nginx.conf",
                    "sites_available_dir": "/etc/nginx/sites-available",
                    "sites_enabled_dir": "/etc/nginx/sites-enabled",
                },
                "log_files": self._get_nginx_log_files(),
            }

        except Exception as e:
            self.logger.error(f"Failed to get nginx comprehensive status: {e}")
            return {}

    def _get_nginx_version(self):
        """Get nginx version"""
        try:
            result = subprocess.run(["nginx", "-v"], capture_output=True, text=True)
            if result.returncode == 0:
                # nginx -v outputs to stderr
                version_line = result.stderr.strip()
                # Extract version number
                match = re.search(r"nginx/(\d+\.\d+\.\d+)", version_line)
                if match:
                    return match.group(1)
            return "unknown"
        except:
            return "unknown"

    def _get_nginx_processes(self):
        """Get nginx process information"""
        try:
            result = subprocess.run(["ps", "aux"], capture_output=True, text=True)

            nginx_processes = []
            for line in result.stdout.split("\n"):
                if "nginx" in line and "grep" not in line:
                    parts = line.split()
                    if len(parts) >= 11:
                        nginx_processes.append(
                            {
                                "user": parts[0],
                                "pid": parts[1],
                                "cpu": parts[2],
                                "memory": parts[3],
                                "command": " ".join(parts[10:]),
                            }
                        )

            return nginx_processes

        except Exception as e:
            self.logger.error(f"Failed to get nginx processes: {e}")
            return []

    def _get_nginx_enabled_sites(self):
        """Get all nginx enabled sites with their configurations"""
        try:
            enabled_sites = []
            enabled_dir = "/etc/nginx/sites-enabled"

            if os.path.exists(enabled_dir):
                for site_file in os.listdir(enabled_dir):
                    site_path = os.path.join(enabled_dir, site_file)

                    if os.path.isfile(site_path) or os.path.islink(site_path):
                        # Get the target of the symlink if it's a link
                        target = None
                        if os.path.islink(site_path):
                            target = os.readlink(site_path)

                        # Parse the configuration
                        config_info = self._parse_nginx_config(site_path)

                        enabled_sites.append(
                            {
                                "name": site_file,
                                "config_file": site_path,
                                "target_file": target,
                                "is_symlink": os.path.islink(site_path),
                                "last_modified": self._get_file_modification_time(
                                    site_path
                                ),
                                "config": config_info,
                            }
                        )

            return enabled_sites

        except Exception as e:
            self.logger.error(f"Failed to get nginx enabled sites: {e}")
            return []

    def _parse_nginx_config(self, config_file):
        """Parse nginx configuration file to extract key information"""
        try:
            if not os.path.exists(config_file):
                return {}

            with open(config_file, "r") as f:
                content = f.read()

            return self._parse_nginx_config_content(content)

        except Exception as e:
            self.logger.error(f"Failed to parse nginx config {config_file}: {e}")
            return {}

    def _parse_nginx_config_content(self, content):
        """Parse nginx configuration content"""
        try:
            config_info = {
                "server_names": [],
                "listen_ports": [],
                "locations": [],
                "ssl_enabled": False,
                "root_directory": None,
                "proxy_pass": None,
            }

            # Extract server names
            server_name_matches = re.findall(r"server_name\s+([^;]+);", content)
            for match in server_name_matches:
                config_info["server_names"].extend(
                    [name.strip() for name in match.split()]
                )

            # Extract listen ports
            listen_matches = re.findall(r"listen\s+([^;]+);", content)
            for match in listen_matches:
                port_info = match.strip()
                config_info["listen_ports"].append(port_info)
                if "ssl" in port_info or "443" in port_info:
                    config_info["ssl_enabled"] = True

            # Extract root directory
            root_match = re.search(r"root\s+([^;]+);", content)
            if root_match:
                config_info["root_directory"] = root_match.group(1).strip()

            # Extract proxy_pass
            proxy_match = re.search(r"proxy_pass\s+([^;]+);", content)
            if proxy_match:
                config_info["proxy_pass"] = proxy_match.group(1).strip()

            # Extract location blocks
            location_matches = re.findall(
                r"location\s+([^{]+)\s*{([^}]*)}", content, re.DOTALL
            )
            for match in location_matches:
                location_path = match[0].strip()
                location_content = match[1].strip()
                config_info["locations"].append(
                    {"path": location_path, "config": location_content}
                )

            return config_info

        except Exception as e:
            self.logger.error(f"Failed to parse nginx config content: {e}")
            return {}

    def _get_comprehensive_network_info(self):
        """Get comprehensive server network information"""
        try:
            network_info = {
                "hostname": socket.gethostname(),
                "interfaces": self._get_all_server_ips(),
                "dns_servers": self._get_dns_servers(),
                "routing_info": self._get_routing_info(),
                "open_ports": self._get_open_ports(),
                "firewall_status": self._get_firewall_status(),
            }

            return network_info

        except Exception as e:
            self.logger.error(f"Failed to get network info: {e}")
            return {}

    def _test_all_sites_connectivity(self):
        """Test connectivity to all hosted sites"""
        connectivity_results = []

        try:
            sites_info = self._get_comprehensive_sites_info()

            for site in sites_info:
                domain_name = site["domain_name"]
                port = site["port"]
                connectivity = self._test_site_connectivity(domain_name, port)

                # Flatten connectivity results
                for conn_test in connectivity:
                    conn_test["domain_name"] = domain_name
                    conn_test["site_type"] = site["site_type"]
                    connectivity_results.append(conn_test)

        except Exception as e:
            self.logger.error(f"Failed to test all sites connectivity: {e}")

        return connectivity_results

    # Utility helper methods
    def _get_dns_servers(self):
        """Get DNS server configuration"""
        try:
            dns_servers = []
            if os.path.exists("/etc/resolv.conf"):
                with open("/etc/resolv.conf", "r") as f:
                    for line in f:
                        if line.startswith("nameserver"):
                            dns_server = line.split()[1]
                            dns_servers.append(dns_server)
            return dns_servers
        except:
            return []

    def _get_routing_info(self):
        """Get basic routing information"""
        try:
            result = subprocess.run(["ip", "route"], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.split("\n")[:10]  # First 10 routes
        except:
            pass
        return []

    def _get_open_ports(self):
        """Get open ports on the server"""
        try:
            result = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
            if result.returncode == 0:
                ports = []
                for line in result.stdout.split("\n")[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 4:
                            local_address = parts[3]
                            if ":" in local_address:
                                port = local_address.split(":")[-1]
                                if port.isdigit():
                                    ports.append(
                                        {
                                            "port": int(port),
                                            "protocol": parts[0],
                                            "address": local_address,
                                        }
                                    )
                return sorted(ports, key=lambda x: x["port"])[:50]  # First 50 ports
        except:
            pass
        return []

    def _get_firewall_status(self):
        """Get firewall status"""
        try:
            # Check UFW
            result = subprocess.run(["ufw", "status"], capture_output=True, text=True)
            if result.returncode == 0:
                return {
                    "type": "ufw",
                    "status": (
                        "active" if "Status: active" in result.stdout else "inactive"
                    ),
                    "details": result.stdout,
                }
        except:
            pass

        try:
            # Check iptables
            result = subprocess.run(["iptables", "-L"], capture_output=True, text=True)
            if result.returncode == 0:
                return {
                    "type": "iptables",
                    "status": "configured",
                    "rule_count": len(result.stdout.split("\n")),
                }
        except:
            pass

        return {"type": "unknown", "status": "unknown"}

    def _get_file_modification_time(self, filepath):
        """Get file modification time"""
        try:
            if os.path.exists(filepath):
                mtime = os.path.getmtime(filepath)
                return datetime.fromtimestamp(mtime).isoformat()
        except:
            pass
        return None

    def _get_os_info(self):
        """Get operating system information"""
        try:
            import platform

            return {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "architecture": platform.architecture()[0],
                "processor": platform.processor(),
            }
        except:
            return {}

    def _get_nginx_log_files(self):
        """Get nginx log file paths"""
        return {
            "access_log": "/var/log/nginx/access.log",
            "error_log": "/var/log/nginx/error.log",
        }

    def _get_nginx_only_sites(self):
        """Get sites that exist in nginx but not in database"""
        # This would check nginx configs for sites not in database
        # Implementation would depend on specific requirements
        return []

    def _detailed_connectivity_test(self, domain_name, port):
        """Perform detailed connectivity testing"""
        basic_test = self._test_site_connectivity(domain_name, port)

        try:
            # Add DNS resolution test
            dns_test = {}
            try:
                ip_address = socket.gethostbyname(domain_name)
                dns_test = {"domain_resolves": True, "resolved_ip": ip_address}
            except socket.gaierror as e:
                dns_test = {"domain_resolves": False, "dns_error": str(e)}

            # Add port connectivity test
            port_test = {}
            if port:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex(("localhost", port))
                    sock.close()

                    port_test = {"port_open": result == 0, "port": port}
                except Exception as e:
                    port_test = {"port_open": False, "port": port, "error": str(e)}

            return {
                "http_tests": basic_test,
                "dns_test": dns_test,
                "port_test": port_test,
            }

        except Exception as e:
            self.logger.error(f"Failed detailed connectivity test: {e}")
            return {"http_tests": basic_test}

    def _get_detailed_directory_info(self, domain_name):
        """Get detailed directory information including file listing"""
        basic_info = self._get_site_directory_info(domain_name)

        if basic_info.get("exists"):
            try:
                site_path = basic_info["path"]

                # Get file listing
                files = []
                for root, dirs, filenames in os.walk(site_path):
                    for filename in filenames:
                        filepath = os.path.join(root, filename)
                        rel_path = os.path.relpath(filepath, site_path)

                        try:
                            stat_info = os.stat(filepath)
                            files.append(
                                {
                                    "name": filename,
                                    "path": rel_path,
                                    "size": stat_info.st_size,
                                    "modified": datetime.fromtimestamp(
                                        stat_info.st_mtime
                                    ).isoformat(),
                                    "permissions": oct(stat_info.st_mode)[-3:],
                                }
                            )
                        except OSError:
                            pass

                basic_info["files"] = sorted(
                    files, key=lambda x: x["modified"], reverse=True
                )[
                    :20
                ]  # Latest 20 files

            except Exception as e:
                self.logger.error(f"Failed to get detailed directory info: {e}")

        return basic_info

    def _get_site_logs(self, domain_name):
        """Get site logs"""
        try:
            return self.process_monitor.get_process_logs(domain_name, 20)
        except:
            return []

    def _get_site_performance_info(self, domain_name, port):
        """Get site performance information"""
        # Basic performance info - could be expanded
        return {"avg_response_time": 0, "uptime_percentage": 0, "error_rate": 0}

    def _get_detailed_process_info(self, domain_name):
        """Get detailed process information"""
        try:
            return self.process_monitor.get_process_details(domain_name)
        except:
            return {}

    def _get_site_process_info(self, domain_name):
        """Get basic process information for a site"""
        try:
            processes = self.process_monitor.get_all_processes()
            return next((p for p in processes if p["name"] == domain_name), None)
        except:
            return None

    def _test_nginx_config_for_site(self, domain_name):
        """Test nginx configuration for a specific site"""
        try:
            result = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def _is_port_available(self, port):
        """Check if a port is available"""
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
