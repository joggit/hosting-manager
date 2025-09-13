# src/api/services/nginx_service.py - Nginx information service
import os
import socket
import subprocess
from pathlib import Path
from datetime import datetime


class NginxService:
    """Service for nginx-related operations"""

    def __init__(self, deps):
        self.hosting_manager = deps["hosting_manager"]
        self.health_checker = deps["health_checker"]
        self.config = deps["config"]
        self.logger = deps["logger"]

    def get_comprehensive_status(self):
        """Get comprehensive nginx status"""
        try:
            # Check service status
            nginx_running = self.hosting_manager._check_service_status("nginx")
            config_valid = self.hosting_manager._test_nginx_config()

            # Get nginx version
            try:
                result = subprocess.run(["nginx", "-v"], capture_output=True, text=True)
                version = (
                    result.stderr.split()[2] if result.returncode == 0 else "unknown"
                )
            except:
                version = "unknown"

            return {
                "service_status": {
                    "running": nginx_running,
                    "version": version,
                },
                "configuration": {
                    "valid": config_valid,
                    "test_output": self._get_config_test_output(),
                },
                "sites": self._get_sites_summary(),
                "logs": self._get_recent_nginx_logs(),
            }
        except Exception as e:
            self.logger.error(f"Failed to get nginx status: {e}")
            return {"error": str(e)}

    def get_enabled_sites(self):
        """Get all nginx enabled sites"""
        enabled_sites = []
        sites_enabled_dir = "/etc/nginx/sites-enabled"

        if os.path.exists(sites_enabled_dir):
            for filename in os.listdir(sites_enabled_dir):
                site_path = os.path.join(sites_enabled_dir, filename)
                if os.path.isfile(site_path) or os.path.islink(site_path):
                    enabled_sites.append(
                        {
                            "name": filename,
                            "path": site_path,
                            "is_link": os.path.islink(site_path),
                            "target": (
                                os.readlink(site_path)
                                if os.path.islink(site_path)
                                else None
                            ),
                            "last_modified": self._get_file_modification_time(
                                site_path
                            ),
                        }
                    )

        return enabled_sites

    def get_comprehensive_sites_info(self):
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

                for row in cursor.fetchall():
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
                        "nginx_config": self.get_nginx_config_info(domain_name),
                        "directory_info": self._get_site_directory_info(domain_name),
                        "health": self.health_checker.get_domain_health(domain_name),
                        "connectivity": self._test_site_connectivity(domain_name, port),
                    }

                    sites_info.append(site_info)

                conn.close()

        except Exception as e:
            self.logger.error(f"Failed to get sites info: {e}")

        return sites_info

    def get_site_detailed_info(self, domain_name):
        """Get detailed information about a specific site"""
        try:
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

                    return {
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
                            "config_content": self.get_nginx_config_content(
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
                    }

        except Exception as e:
            self.logger.error(f"Failed to get site details for {domain_name}: {e}")

        return None

    def get_nginx_config_content(self, domain_name):
        """Get nginx configuration file content"""
        try:
            config_file = f"/etc/nginx/sites-available/{domain_name}"
            if os.path.exists(config_file):
                with open(config_file, "r") as f:
                    return f.read()
        except Exception as e:
            self.logger.error(f"Failed to read nginx config for {domain_name}: {e}")
        return None

    def get_nginx_config_info(self, domain_name):
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

    def parse_nginx_config_content(self, content):
        """Parse nginx configuration content"""
        # Basic parsing - could be enhanced
        config_info = {
            "server_names": [],
            "listen_ports": [],
            "root_directories": [],
            "proxy_passes": [],
        }

        try:
            lines = content.split("\n")
            for line in lines:
                line = line.strip()
                if line.startswith("server_name"):
                    # Extract server names
                    parts = line.split()
                    if len(parts) > 1:
                        config_info["server_names"].extend(parts[1:])
                elif line.startswith("listen"):
                    # Extract listen ports
                    parts = line.split()
                    if len(parts) > 1:
                        config_info["listen_ports"].append(parts[1].rstrip(";"))
                elif line.startswith("root"):
                    # Extract root directories
                    parts = line.split()
                    if len(parts) > 1:
                        config_info["root_directories"].append(parts[1].rstrip(";"))
                elif "proxy_pass" in line:
                    # Extract proxy passes
                    parts = line.split()
                    proxy_idx = next(
                        (i for i, p in enumerate(parts) if "proxy_pass" in p), -1
                    )
                    if proxy_idx >= 0 and proxy_idx + 1 < len(parts):
                        config_info["proxy_passes"].append(
                            parts[proxy_idx + 1].rstrip(";")
                        )
        except Exception as e:
            self.logger.error(f"Failed to parse nginx config: {e}")

        return config_info

    def test_all_sites_connectivity(self):
        """Test connectivity to all hosted sites"""
        connectivity_results = []

        try:
            domains = self.hosting_manager.list_domains()
            for domain in domains:
                result = self._test_site_connectivity(
                    domain["domain_name"], domain["port"]
                )
                connectivity_results.append(result)
        except Exception as e:
            self.logger.error(f"Failed to test sites connectivity: {e}")

        return connectivity_results

    def get_server_info(self):
        """Get server information"""
        try:
            hostname = socket.gethostname()

            # Get primary IP address
            try:
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
                "nginx_version": self._get_nginx_version(),
            }
        except Exception as e:
            self.logger.error(f"Failed to get server info: {e}")
            return {}

    def get_comprehensive_network_info(self):
        """Get comprehensive network information"""
        try:
            import psutil

            # Get network interfaces
            interfaces = {}
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {"addresses": [], "stats": None}

                for addr in addrs:
                    interface_info["addresses"].append(
                        {
                            "family": str(addr.family),
                            "address": addr.address,
                            "netmask": addr.netmask,
                            "broadcast": addr.broadcast,
                        }
                    )

                # Get interface stats
                try:
                    stats = psutil.net_if_stats()[interface]
                    interface_info["stats"] = {
                        "is_up": stats.isup,
                        "duplex": str(stats.duplex),
                        "speed": stats.speed,
                        "mtu": stats.mtu,
                    }
                except:
                    pass

                interfaces[interface] = interface_info

            # Get network connections
            connections = []
            try:
                for conn in psutil.net_connections():
                    if conn.status == "LISTEN":
                        connections.append(
                            {
                                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                                "status": conn.status,
                                "pid": conn.pid,
                            }
                        )
            except:
                pass

            return {
                "interfaces": interfaces,
                "listening_connections": connections,
                "io_counters": self._get_network_io_counters(),
            }

        except Exception as e:
            self.logger.error(f"Failed to get network info: {e}")
            return {}

    # Helper methods
    def _get_config_test_output(self):
        """Get nginx config test output"""
        try:
            result = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
            return {
                "success": result.returncode == 0,
                "output": result.stderr,
            }
        except:
            return {"success": False, "output": "Could not test configuration"}

    def _get_sites_summary(self):
        """Get summary of nginx sites"""
        available_count = 0
        enabled_count = 0

        if os.path.exists("/etc/nginx/sites-available"):
            available_count = len(
                [
                    f
                    for f in os.listdir("/etc/nginx/sites-available")
                    if os.path.isfile(os.path.join("/etc/nginx/sites-available", f))
                ]
            )

        if os.path.exists("/etc/nginx/sites-enabled"):
            enabled_count = len(
                [
                    f
                    for f in os.listdir("/etc/nginx/sites-enabled")
                    if os.path.isfile(os.path.join("/etc/nginx/sites-enabled", f))
                    or os.path.islink(os.path.join("/etc/nginx/sites-enabled", f))
                ]
            )

        return {
            "available_count": available_count,
            "enabled_count": enabled_count,
        }

    def _get_recent_nginx_logs(self):
        """Get recent nginx logs"""
        logs = {"access": [], "error": []}

        # Access log
        access_log = "/var/log/nginx/access.log"
        if os.path.exists(access_log):
            try:
                with open(access_log, "r") as f:
                    logs["access"] = f.readlines()[-10:]
            except:
                pass

        # Error log
        error_log = "/var/log/nginx/error.log"
        if os.path.exists(error_log):
            try:
                with open(error_log, "r") as f:
                    logs["error"] = f.readlines()[-10:]
            except:
                pass

        return logs

    def _generate_site_urls(self, domain_name, ssl_enabled):
        """Generate URLs for a site"""
        urls = {"http": f"http://{domain_name}", "primary": f"http://{domain_name}"}
        if ssl_enabled:
            urls["https"] = f"https://{domain_name}"
            urls["primary"] = f"https://{domain_name}"
        return urls

    def _get_site_directory_info(self, domain_name):
        """Get site directory information"""
        site_path = f"{self.config.get('web_root')}/{domain_name}"
        info = {
            "path": site_path,
            "exists": os.path.exists(site_path),
        }

        if info["exists"]:
            try:
                stat = os.stat(site_path)
                info.update(
                    {
                        "size": self._get_directory_size(site_path),
                        "last_modified": datetime.fromtimestamp(
                            stat.st_mtime
                        ).isoformat(),
                        "permissions": oct(stat.st_mode)[-3:],
                    }
                )
            except:
                pass

        return info

    def _test_site_connectivity(self, domain_name, port):
        """Test basic connectivity to a site"""
        result = {
            "domain_name": domain_name,
            "port": port,
            "responding": False,
            "response_time": None,
            "error": None,
        }

        try:
            import requests
            import time

            start_time = time.time()
            response = requests.get(f"http://localhost:{port}", timeout=5)
            response_time = (time.time() - start_time) * 1000

            result.update(
                {
                    "responding": True,
                    "response_time": round(response_time, 2),
                    "status_code": response.status_code,
                }
            )
        except Exception as e:
            result["error"] = str(e)

        return result

    def _detailed_connectivity_test(self, domain_name, port):
        """Perform detailed connectivity test"""
        return self._test_site_connectivity(domain_name, port)

    def _get_detailed_directory_info(self, domain_name):
        """Get detailed directory information"""
        return self._get_site_directory_info(domain_name)

    def _test_nginx_config_for_site(self, domain_name):
        """Test nginx configuration for specific site"""
        return self.hosting_manager._test_nginx_config()

    def _get_file_modification_time(self, filepath):
        """Get file modification time"""
        try:
            if os.path.exists(filepath):
                return datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
        except:
            pass
        return None

    def _get_all_server_ips(self):
        """Get all server IP addresses"""
        try:
            import psutil

            ips = []
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ips.append(addr.address)
            return ips
        except:
            return []

    def _get_nginx_version(self):
        """Get nginx version"""
        try:
            result = subprocess.run(["nginx", "-v"], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stderr.split()[2]
        except:
            pass
        return "unknown"

    def _get_directory_size(self, path):
        """Get directory size"""
        try:
            total = 0
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    total += os.path.getsize(filepath)
            return total
        except:
            return 0

    def _get_network_io_counters(self):
        """Get network IO counters"""
        try:
            import psutil

            counters = psutil.net_io_counters()
            return {
                "bytes_sent": counters.bytes_sent,
                "bytes_recv": counters.bytes_recv,
                "packets_sent": counters.packets_sent,
                "packets_recv": counters.packets_recv,
            }
        except:
            return {}
