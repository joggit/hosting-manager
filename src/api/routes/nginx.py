# src/api/routes/nginx.py - Nginx information routes with domain availability checking
import os
import re
import subprocess
import requests
import socket
import psutil
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from flask import request

from ..utils import APIResponse, handle_api_errors


class NginxService:
    """Extended NginxService with domain availability checking"""

    def __init__(self, deps):
        self.config = deps["config"]
        self.logger = deps["logger"]
        self.hosting_manager = deps["hosting_manager"]

    def get_comprehensive_status(self):
        """Get comprehensive nginx status information"""
        try:
            # Check if nginx is running
            nginx_running = self._is_nginx_running()

            status_info = {
                "running": nginx_running,
                "service_status": self._get_service_status(),
                "config_test": self._test_nginx_config(),
                "version": self._get_nginx_version(),
                "worker_processes": self._get_worker_processes(),
                "connections": self._get_connection_stats(),
                "uptime": self._get_nginx_uptime(),
                "error_log": self._get_recent_error_logs(),
            }

            if nginx_running:
                status_info.update(
                    {
                        "listen_addresses": self._get_listen_addresses(),
                        "ssl_certificates": self._get_ssl_certificate_info(),
                    }
                )

            return status_info

        except Exception as e:
            self.logger.error(f"Failed to get nginx status: {e}")
            return {"error": str(e), "running": False}

    def get_enabled_sites(self):
        """Get list of enabled nginx sites"""
        try:
            sites_enabled_dir = self.config.get(
                "nginx_enabled_dir", "/etc/nginx/sites-enabled"
            )

            if not os.path.exists(sites_enabled_dir):
                return []

            enabled_sites = []

            for site_file in os.listdir(sites_enabled_dir):
                site_path = os.path.join(sites_enabled_dir, site_file)

                if os.path.isfile(site_path) or os.path.islink(site_path):
                    site_info = {
                        "name": site_file,
                        "path": site_path,
                        "is_symlink": os.path.islink(site_path),
                        "target": (
                            os.readlink(site_path)
                            if os.path.islink(site_path)
                            else None
                        ),
                        "size": (
                            os.path.getsize(site_path)
                            if not os.path.islink(site_path)
                            else None
                        ),
                        "modified": datetime.fromtimestamp(
                            os.path.getmtime(site_path)
                        ).isoformat(),
                    }

                    # Try to parse config
                    config_content = self.get_nginx_config_content(site_file)
                    if config_content:
                        parsed_config = self.parse_nginx_config_content(config_content)
                        site_info["config"] = parsed_config

                    enabled_sites.append(site_info)

            return enabled_sites

        except Exception as e:
            self.logger.error(f"Failed to get enabled sites: {e}")
            return []

    def get_comprehensive_sites_info(self):
        """Get comprehensive information about all sites"""
        try:
            sites_info = []

            # Get database sites
            db_sites = self._get_database_sites()

            # Get nginx sites
            nginx_sites = self._get_nginx_sites()

            # ✅ NEW: Get PM2 processes
            pm2_processes = self._get_pm2_processes()

            # Merge information from all sources
            all_site_names = set()
            all_site_names.update([site["domain_name"] for site in db_sites])
            all_site_names.update([site["name"] for site in nginx_sites])
            all_site_names.update(
                [proc["name"] for proc in pm2_processes]
            )  # ✅ ADD THIS

            for site_name in all_site_names:
                # Find in database
                db_site = next(
                    (s for s in db_sites if s["domain_name"] == site_name), None
                )

                # Find in nginx
                nginx_site = next(
                    (s for s in nginx_sites if s["name"] == site_name), None
                )

                # ✅ NEW: Find in PM2
                pm2_process = next(
                    (p for p in pm2_processes if p["name"] == site_name), None
                )

                site_info = {
                    "domain_name": site_name,
                    "in_database": db_site is not None,
                    "in_nginx": nginx_site is not None,
                    "in_pm2": pm2_process is not None,  # ✅ ADD THIS
                    "status": "unknown",
                }

                if db_site:
                    site_info.update(
                        {
                            "port": db_site["port"],
                            "site_type": db_site["site_type"],
                            "ssl_enabled": db_site["ssl_enabled"],
                            "created_at": db_site["created_at"],
                            "database_status": db_site["status"],
                        }
                    )

                if nginx_site:
                    site_info.update(
                        {
                            "nginx_config": nginx_site.get("config", {}),
                            "config_path": nginx_site["path"],
                            "is_enabled": nginx_site.get("enabled", False),
                        }
                    )

                # ✅ NEW: Add PM2 process info
                if pm2_process:
                    site_info.update(
                        {
                            "pm2_process": pm2_process,
                            "port": pm2_process.get("port") or site_info.get("port"),
                            "process_status": pm2_process.get("status", "unknown"),
                        }
                    )

                # Determine overall status
                if db_site and nginx_site:
                    site_info["status"] = (
                        "active" if db_site["status"] == "active" else db_site["status"]
                    )
                elif (
                    pm2_process and pm2_process.get("status") == "online"
                ):  # ✅ ADD THIS
                    site_info["status"] = "active"
                elif db_site:
                    site_info["status"] = "database_only"
                elif nginx_site:
                    site_info["status"] = "nginx_only"

                # Test connectivity
                if site_info.get("port"):
                    connectivity = self._test_site_connectivity(
                        site_name, site_info["port"]
                    )
                    site_info["connectivity"] = connectivity

                sites_info.append(site_info)

            return sites_info

        except Exception as e:
            self.logger.error(f"Failed to get comprehensive sites info: {e}")
            return []

    def get_site_detailed_info(self, domain_name):
        """Get detailed information about a specific site"""
        try:
            site_info = {
                "domain_name": domain_name,
                "database": self._get_site_database_info(domain_name),
                "nginx": self._get_site_nginx_info(domain_name),
                "connectivity": None,
                "ssl": None,
                "files": None,
            }

            # Test connectivity if port is available
            if site_info["database"] and site_info["database"].get("port"):
                port = site_info["database"]["port"]
                site_info["connectivity"] = self._test_site_connectivity(
                    domain_name, port
                )

            # Check SSL certificates
            site_info["ssl"] = self._get_site_ssl_info(domain_name)

            # Check files
            site_info["files"] = self._get_site_files_info(domain_name)

            return site_info if site_info["database"] or site_info["nginx"] else None

        except Exception as e:
            self.logger.error(f"Failed to get site details for {domain_name}: {e}")
            return None

    def get_nginx_config_content(self, site_name):
        """Get nginx configuration content for a site"""
        try:
            # Check sites-enabled first
            sites_enabled_dir = self.config.get(
                "nginx_enabled_dir", "/etc/nginx/sites-enabled"
            )
            enabled_path = os.path.join(sites_enabled_dir, site_name)

            if os.path.exists(enabled_path):
                with open(enabled_path, "r") as f:
                    return f.read()

            # Check sites-available
            sites_available_dir = self.config.get(
                "nginx_sites_dir", "/etc/nginx/sites-available"
            )
            available_path = os.path.join(sites_available_dir, site_name)

            if os.path.exists(available_path):
                with open(available_path, "r") as f:
                    return f.read()

            return None

        except Exception as e:
            self.logger.warning(f"Failed to read nginx config for {site_name}: {e}")
            return None

    def get_nginx_config_info(self, domain_name):
        """Get nginx configuration file information"""
        try:
            config_info = {
                "sites_available": None,
                "sites_enabled": None,
                "is_enabled": False,
            }

            sites_available_dir = self.config.get(
                "nginx_sites_dir", "/etc/nginx/sites-available"
            )
            sites_enabled_dir = self.config.get(
                "nginx_enabled_dir", "/etc/nginx/sites-enabled"
            )

            available_path = os.path.join(sites_available_dir, domain_name)
            enabled_path = os.path.join(sites_enabled_dir, domain_name)

            if os.path.exists(available_path):
                stat = os.stat(available_path)
                config_info["sites_available"] = {
                    "path": available_path,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "is_symlink": os.path.islink(available_path),
                }

            if os.path.exists(enabled_path):
                stat = os.stat(enabled_path)
                config_info["sites_enabled"] = {
                    "path": enabled_path,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "is_symlink": os.path.islink(enabled_path),
                    "target": (
                        os.readlink(enabled_path)
                        if os.path.islink(enabled_path)
                        else None
                    ),
                }
                config_info["is_enabled"] = True

            return config_info

        except Exception as e:
            self.logger.error(f"Failed to get nginx config info for {domain_name}: {e}")
            return None

    def parse_nginx_config_content(self, config_content):
        """Parse nginx configuration content"""
        try:
            parsed = {
                "server_names": [],
                "listen_ports": [],
                "root_path": None,
                "ssl_certificate": None,
                "ssl_certificate_key": None,
                "proxy_pass": None,
                "locations": [],
            }

            # Extract server_name
            server_name_matches = re.findall(r"server_name\s+([^;]+);", config_content)
            for match in server_name_matches:
                names = [name.strip() for name in match.split()]
                parsed["server_names"].extend(names)

            # Extract listen ports
            listen_matches = re.findall(r"listen\s+([^;]+);", config_content)
            for match in listen_matches:
                parsed["listen_ports"].append(match.strip())

            # Extract root path
            root_match = re.search(r"root\s+([^;]+);", config_content)
            if root_match:
                parsed["root_path"] = root_match.group(1).strip()

            # Extract SSL certificate paths
            ssl_cert_match = re.search(r"ssl_certificate\s+([^;]+);", config_content)
            if ssl_cert_match:
                parsed["ssl_certificate"] = ssl_cert_match.group(1).strip()

            ssl_key_match = re.search(r"ssl_certificate_key\s+([^;]+);", config_content)
            if ssl_key_match:
                parsed["ssl_certificate_key"] = ssl_key_match.group(1).strip()

            # Extract proxy_pass
            proxy_matches = re.findall(r"proxy_pass\s+([^;]+);", config_content)
            if proxy_matches:
                parsed["proxy_pass"] = proxy_matches[0].strip()

            # Extract location blocks
            location_matches = re.findall(
                r"location\s+([^{]+)\s*{([^}]*)}", config_content, re.DOTALL
            )
            for location_path, location_content in location_matches:
                location_info = {
                    "path": location_path.strip(),
                    "content": location_content.strip(),
                }

                # Parse location-specific directives
                if "proxy_pass" in location_content:
                    proxy_match = re.search(r"proxy_pass\s+([^;]+);", location_content)
                    if proxy_match:
                        location_info["proxy_pass"] = proxy_match.group(1).strip()

                if "try_files" in location_content:
                    try_files_match = re.search(
                        r"try_files\s+([^;]+);", location_content
                    )
                    if try_files_match:
                        location_info["try_files"] = try_files_match.group(1).strip()

                parsed["locations"].append(location_info)

            return parsed

        except Exception as e:
            self.logger.error(f"Failed to parse nginx config: {e}")
            return {}

    def test_all_sites_connectivity(self):
        """Test connectivity for all sites"""
        try:
            sites = self.get_comprehensive_sites_info()
            connectivity_results = []

            for site in sites:
                if site.get("port"):
                    result = self._test_site_connectivity(
                        site["domain_name"], site["port"]
                    )
                    connectivity_results.append(
                        {
                            "domain_name": site["domain_name"],
                            "port": site["port"],
                            **result,
                        }
                    )

            return connectivity_results

        except Exception as e:
            self.logger.error(f"Failed to test sites connectivity: {e}")
            return []

    def get_comprehensive_network_info(self):
        """Get comprehensive network information"""
        try:
            network_info = {
                "interfaces": self._get_network_interfaces(),
                "listening_ports": self._get_listening_ports(),
                "nginx_processes": self._get_nginx_processes(),
                "connections": self._get_active_connections(),
                "dns_info": self._get_dns_info(),
            }

            return network_info

        except Exception as e:
            self.logger.error(f"Failed to get network info: {e}")
            return {}

    def get_server_info(self):
        """Get server information"""
        try:
            return {
                "hostname": socket.gethostname(),
                "fqdn": socket.getfqdn(),
                "ip_addresses": self._get_server_ip_addresses(),
                "nginx_version": self._get_nginx_version(),
                "uptime": self._get_system_uptime(),
                "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None,
            }
        except Exception as e:
            self.logger.error(f"Failed to get server info: {e}")
            return {}

    # NEW METHODS for domain availability checking

    def check_domain_availability_in_nginx(self, domain_name: str) -> Dict:
        """
        Check if domain exists in nginx configurations
        Returns comprehensive results for both sites-available and sites-enabled
        """
        results = {
            "nginx_available": {"available": True, "details": {}, "message": ""},
            "nginx_enabled": {"available": True, "details": {}, "message": ""},
        }

        # Check sites-available
        sites_available_dir = self.config.get(
            "nginx_sites_dir", "/etc/nginx/sites-available"
        )
        results["nginx_available"] = self._check_domain_in_directory(
            sites_available_dir, domain_name, "sites-available"
        )

        # Check sites-enabled
        sites_enabled_dir = self.config.get(
            "nginx_enabled_dir", "/etc/nginx/sites-enabled"
        )
        results["nginx_enabled"] = self._check_domain_in_directory(
            sites_enabled_dir, domain_name, "sites-enabled"
        )

        return results

    def is_domain_in_nginx(self, domain_name: str) -> Tuple[bool, List[str]]:
        """
        Simple check if domain exists in nginx - returns (exists, locations)
        """
        nginx_results = self.check_domain_availability_in_nginx(domain_name)

        conflicts = []
        for location, result in nginx_results.items():
            if not result["available"]:
                conflicts.append(location)

        return len(conflicts) > 0, conflicts

    def _check_domain_in_directory(
        self, directory_path: str, domain_name: str, dir_type: str
    ) -> Dict:
        """Check if domain exists in specific nginx directory"""
        result = {
            "available": True,
            "details": {},
            "message": "",
            "directory": directory_path,
        }

        if not os.path.exists(directory_path):
            result["message"] = f"nginx {dir_type} directory not found"
            return result

        try:
            # 1. Check for direct config file match
            direct_config_path = os.path.join(directory_path, domain_name)

            if os.path.exists(direct_config_path):
                result["available"] = False
                result["details"] = {
                    "config_file": direct_config_path,
                    "file_type": "direct_match",
                    "is_symlink": os.path.islink(direct_config_path),
                }

                if os.path.islink(direct_config_path):
                    result["details"]["target"] = os.readlink(direct_config_path)
                    result["message"] = f"Domain symlink exists: {direct_config_path}"
                else:
                    result["message"] = (
                        f"Domain config file exists: {direct_config_path}"
                    )

                return result

            # 2. Scan all config files for server_name matches
            for config_file in os.listdir(directory_path):
                config_path = os.path.join(directory_path, config_file)

                # Skip directories and hidden files
                if os.path.isdir(config_path) or config_file.startswith("."):
                    continue

                # Try to read config content
                config_content = self._read_config_file_safe(config_path)

                if config_content and self._domain_in_config_content(
                    config_content, domain_name
                ):
                    result["available"] = False
                    result["details"] = {
                        "config_file": config_path,
                        "file_type": "server_name_match",
                        "matched_in_file": config_file,
                    }
                    result["message"] = (
                        f"Domain found in server_name directive in: {config_path}"
                    )
                    return result

        except Exception as e:
            self.logger.error(f"Error checking nginx {dir_type}: {e}")
            result["message"] = f"Directory check failed: {str(e)}"

        return result

    def _read_config_file_safe(self, config_path: str) -> Optional[str]:
        """Safely read nginx config file content"""
        try:
            with open(config_path, "r") as f:
                return f.read()
        except Exception as e:
            self.logger.warning(f"Could not read nginx config file {config_path}: {e}")
            return None

    def _domain_in_config_content(self, config_content: str, domain_name: str) -> bool:
        """Check if domain appears in nginx config content"""
        # Try to use existing parsing method
        try:
            parsed_config = self.parse_nginx_config_content(config_content)
            # Check if parsed config contains our domain
            if isinstance(parsed_config, dict):
                server_names = parsed_config.get("server_names", [])
                if isinstance(server_names, list):
                    return domain_name in server_names
                elif isinstance(server_names, str):
                    return domain_name in server_names.split()
        except:
            pass  # Fall back to regex parsing

        # Fallback to regex parsing
        return self._regex_parse_server_names(config_content, domain_name)

    def _regex_parse_server_names(self, config_content: str, domain_name: str) -> bool:
        """Regex-based server_name parsing as fallback"""
        server_name_pattern = r"server_name\s+([^;]+);"
        matches = re.findall(server_name_pattern, config_content, re.IGNORECASE)

        for match in matches:
            domains = [d.strip() for d in match.split()]

            if domain_name in domains:
                return True

            # Check for wildcard matches
            for configured_domain in domains:
                if configured_domain.startswith("*."):
                    wildcard_base = configured_domain[2:]
                    if domain_name.endswith(wildcard_base):
                        return True

        return False

    # PRIVATE HELPER METHODS

    def _is_nginx_running(self):
        """Check if nginx is running"""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "nginx"], capture_output=True, text=True
            )
            return result.returncode == 0
        except:
            # Fallback to process check
            try:
                subprocess.run(["pgrep", "nginx"], check=True, capture_output=True)
                return True
            except:
                return False

    def _get_service_status(self):
        """Get systemd service status"""
        try:
            result = subprocess.run(
                ["systemctl", "status", "nginx"], capture_output=True, text=True
            )
            return {
                "active": "active" in result.stdout,
                "enabled": self._is_service_enabled(),
                "exit_code": result.returncode,
            }
        except:
            return {"active": False, "enabled": False, "exit_code": -1}

    def _is_service_enabled(self):
        """Check if nginx service is enabled"""
        try:
            result = subprocess.run(
                ["systemctl", "is-enabled", "nginx"], capture_output=True, text=True
            )
            return result.returncode == 0
        except:
            return False

    def _test_nginx_config(self):
        """Test nginx configuration"""
        try:
            result = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
            return {"valid": result.returncode == 0, "output": result.stderr.strip()}
        except:
            return {"valid": False, "output": "Failed to test config"}

    def _get_nginx_version(self):
        """Get nginx version"""
        try:
            result = subprocess.run(["nginx", "-v"], capture_output=True, text=True)
            version_line = result.stderr.strip()
            if "nginx/" in version_line:
                return version_line.split("nginx/")[1].split()[0]
            return "unknown"
        except:
            return "unknown"

    def _get_worker_processes(self):
        """Get nginx worker process count"""
        try:
            procs = []
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                if proc.info["name"] == "nginx":
                    procs.append(
                        {
                            "pid": proc.info["pid"],
                            "cmdline": (
                                " ".join(proc.info["cmdline"])
                                if proc.info["cmdline"]
                                else ""
                            ),
                        }
                    )
            return procs
        except:
            return []

    def _get_connection_stats(self):
        """Get connection statistics"""
        try:
            stats = {"http": 0, "https": 0, "total": 0}

            for conn in psutil.net_connections():
                if conn.laddr and conn.laddr.port in [80, 8080]:
                    stats["http"] += 1
                elif conn.laddr and conn.laddr.port in [443, 8443]:
                    stats["https"] += 1
                stats["total"] += 1

            return stats
        except:
            return {"http": 0, "https": 0, "total": 0}

    def _get_nginx_uptime(self):
        """Get nginx uptime"""
        try:
            for proc in psutil.process_iter(["pid", "name", "create_time"]):
                if proc.info["name"] == "nginx":
                    create_time = datetime.fromtimestamp(proc.info["create_time"])
                    uptime = datetime.now() - create_time
                    return {
                        "start_time": create_time.isoformat(),
                        "uptime_seconds": uptime.total_seconds(),
                        "uptime_human": str(uptime),
                    }
            return None
        except:
            return None

    def _get_recent_error_logs(self, lines=10):
        """Get recent nginx error log entries"""
        try:
            error_log_paths = [
                "/var/log/nginx/error.log",
                "/usr/local/nginx/logs/error.log",
            ]

            for log_path in error_log_paths:
                if os.path.exists(log_path):
                    with open(log_path, "r") as f:
                        log_lines = f.readlines()
                        return (
                            log_lines[-lines:] if len(log_lines) > lines else log_lines
                        )

            return []
        except:
            return []

    def _get_listen_addresses(self):
        """Get nginx listening addresses"""
        try:
            addresses = []
            for conn in psutil.net_connections():
                if conn.laddr and conn.laddr.port in [80, 443, 8080, 8443]:
                    addresses.append(f"{conn.laddr.ip}:{conn.laddr.port}")
            return list(set(addresses))
        except:
            return []

    def _get_pm2_processes(self):
        """Get running PM2 processes"""
        try:
            import subprocess
            import json

            result = subprocess.run(
                ["pm2", "jlist"], capture_output=True, text=True, timeout=5
            )

            if result.returncode != 0:
                return []

            processes = json.loads(result.stdout)

            pm2_list = []
            for proc in processes:
                pm2_info = {
                    "name": proc.get("name"),
                    "pm2_id": proc.get("pm_id"),
                    "status": proc.get("pm2_env", {}).get("status", "unknown"),
                    "pid": proc.get("pid"),
                    "port": None,  # Try to extract from env
                    "cwd": proc.get("pm2_env", {}).get("pm_cwd"),
                }

                # Try to get port from environment
                env = proc.get("pm2_env", {})
                if "PORT" in env:
                    try:
                        pm2_info["port"] = int(env["PORT"])
                    except:
                        pass

                pm2_list.append(pm2_info)

            return pm2_list

        except Exception as e:
            self.logger.error(f"Failed to get PM2 processes: {e}")
            return []

    def _get_ssl_certificate_info(self):
        """Get SSL certificate information"""
        try:
            cert_info = []

            # Common certificate paths
            cert_paths = [
                "/etc/ssl/certs/",
                "/etc/nginx/ssl/",
                "/etc/letsencrypt/live/",
            ]

            for cert_dir in cert_paths:
                if os.path.exists(cert_dir):
                    for item in os.listdir(cert_dir):
                        item_path = os.path.join(cert_dir, item)
                        if os.path.isfile(item_path) and item.endswith(
                            (".crt", ".pem")
                        ):
                            try:
                                stat = os.stat(item_path)
                                cert_info.append(
                                    {
                                        "path": item_path,
                                        "name": item,
                                        "size": stat.st_size,
                                        "modified": datetime.fromtimestamp(
                                            stat.st_mtime
                                        ).isoformat(),
                                    }
                                )
                            except:
                                continue

            return cert_info
        except:
            return []

    def _get_database_sites(self):
        """Get sites from database"""
        try:
            conn = self.hosting_manager.get_database_connection()
            if not conn:
                return []

            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT domain_name, port, site_type, ssl_enabled, status, created_at
                FROM domains
                ORDER BY created_at DESC
            """
            )

            sites = []
            for row in cursor.fetchall():
                sites.append(
                    {
                        "domain_name": row[0],
                        "port": row[1],
                        "site_type": row[2],
                        "ssl_enabled": bool(row[3]),
                        "status": row[4],
                        "created_at": row[5],
                    }
                )

            conn.close()
            return sites
        except Exception as e:
            self.logger.error(f"Failed to get database sites: {e}")
            return []

    def _get_nginx_sites(self):
        """Get sites from nginx configuration"""
        try:
            sites = []

            # Check sites-available
            sites_available_dir = self.config.get(
                "nginx_sites_dir", "/etc/nginx/sites-available"
            )
            sites_enabled_dir = self.config.get(
                "nginx_enabled_dir", "/etc/nginx/sites-enabled"
            )

            if os.path.exists(sites_available_dir):
                for site_file in os.listdir(sites_available_dir):
                    site_path = os.path.join(sites_available_dir, site_file)

                    if os.path.isfile(site_path):
                        enabled_path = os.path.join(sites_enabled_dir, site_file)

                        site_info = {
                            "name": site_file,
                            "path": site_path,
                            "enabled": os.path.exists(enabled_path),
                        }

                        # Parse config
                        config_content = self.get_nginx_config_content(site_file)
                        if config_content:
                            site_info["config"] = self.parse_nginx_config_content(
                                config_content
                            )

                        sites.append(site_info)

            return sites
        except Exception as e:
            self.logger.error(f"Failed to get nginx sites: {e}")
            return []

    def _get_site_database_info(self, domain_name):
        """Get database information for a site"""
        try:
            conn = self.hosting_manager.get_database_connection()
            if not conn:
                return None

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
                return {
                    "domain_name": row[0],
                    "port": row[1],
                    "site_type": row[2],
                    "ssl_enabled": bool(row[3]),
                    "status": row[4],
                    "created_at": row[5],
                    "updated_at": row[6],
                }

            return None
        except Exception as e:
            self.logger.error(f"Failed to get database info for {domain_name}: {e}")
            return None

    def _get_site_nginx_info(self, domain_name):
        """Get nginx information for a site"""
        try:
            nginx_info = {
                "config_exists": False,
                "enabled": False,
                "config_content": None,
                "parsed_config": None,
            }

            config_content = self.get_nginx_config_content(domain_name)
            if config_content:
                nginx_info["config_exists"] = True
                nginx_info["config_content"] = config_content
                nginx_info["parsed_config"] = self.parse_nginx_config_content(
                    config_content
                )

            # Check if enabled
            sites_enabled_dir = self.config.get(
                "nginx_enabled_dir", "/etc/nginx/sites-enabled"
            )
            enabled_path = os.path.join(sites_enabled_dir, domain_name)
            nginx_info["enabled"] = os.path.exists(enabled_path)

            return nginx_info if nginx_info["config_exists"] else None

        except Exception as e:
            self.logger.error(f"Failed to get nginx info for {domain_name}: {e}")
            return None

    def _test_site_connectivity(self, domain_name, port):
        """Test connectivity to a site"""
        try:
            connectivity = {
                "responding": False,
                "status_code": None,
                "response_time": None,
                "error": None,
            }

            # Test HTTP connection
            try:
                start_time = datetime.now()
                response = requests.get(
                    f"http://localhost:{port}", timeout=5, headers={"Host": domain_name}
                )
                end_time = datetime.now()

                connectivity["responding"] = True
                connectivity["status_code"] = response.status_code
                connectivity["response_time"] = (end_time - start_time).total_seconds()

            except requests.exceptions.RequestException as e:
                connectivity["error"] = str(e)

            return connectivity

        except Exception as e:
            return {"responding": False, "error": str(e)}

    def _get_site_ssl_info(self, domain_name):
        """Get SSL information for a site"""
        try:
            ssl_info = {
                "certificate_exists": False,
                "certificate_path": None,
                "key_path": None,
                "expiry_date": None,
            }

            # Check common SSL paths
            ssl_paths = [
                f"/etc/letsencrypt/live/{domain_name}/fullchain.pem",
                f"/etc/ssl/certs/{domain_name}.crt",
                f"/etc/nginx/ssl/{domain_name}.crt",
            ]

            for cert_path in ssl_paths:
                if os.path.exists(cert_path):
                    ssl_info["certificate_exists"] = True
                    ssl_info["certificate_path"] = cert_path

                    # Try to get certificate info
                    try:
                        result = subprocess.run(
                            ["openssl", "x509", "-in", cert_path, "-noout", "-enddate"],
                            capture_output=True,
                            text=True,
                        )

                        if result.returncode == 0:
                            # Parse expiry date
                            for line in result.stdout.split("\n"):
                                if "notAfter=" in line:
                                    ssl_info["expiry_date"] = line.split("notAfter=")[
                                        1
                                    ].strip()
                    except:
                        pass

                    break

            return ssl_info

        except Exception as e:
            self.logger.error(f"Failed to get SSL info for {domain_name}: {e}")
            return {}

    def _get_site_files_info(self, domain_name):
        """Get file system information for a site"""
        try:
            web_root = self.config.get("web_root", "/tmp/www/domains")
            site_path = os.path.join(web_root, domain_name)

            if not os.path.exists(site_path):
                return {"exists": False}

            files_info = {
                "exists": True,
                "path": site_path,
                "size": self._get_directory_size(site_path),
                "file_count": self._count_files(site_path),
                "modified": datetime.fromtimestamp(
                    os.path.getmtime(site_path)
                ).isoformat(),
            }

            # Check for common files
            common_files = ["index.html", "index.js", "package.json", ".next"]
            for file_name in common_files:
                file_path = os.path.join(site_path, file_name)
                files_info[f"has_{file_name.replace('.', '_')}"] = os.path.exists(
                    file_path
                )

            return files_info

        except Exception as e:
            self.logger.error(f"Failed to get files info for {domain_name}: {e}")
            return {"exists": False, "error": str(e)}

    def _get_directory_size(self, path):
        """Get directory size recursively"""
        try:
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                    except:
                        continue
            return total_size
        except:
            return 0

    def _count_files(self, path):
        """Count files in directory recursively"""
        try:
            count = 0
            for dirpath, dirnames, filenames in os.walk(path):
                count += len(filenames)
            return count
        except:
            return 0

    def _get_network_interfaces(self):
        """Get network interface information"""
        try:
            interfaces = []
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {"name": interface, "addresses": []}

                for addr in addrs:
                    interface_info["addresses"].append(
                        {
                            "family": str(addr.family),
                            "address": addr.address,
                            "netmask": addr.netmask,
                            "broadcast": addr.broadcast,
                        }
                    )

                interfaces.append(interface_info)

            return interfaces
        except:
            return []

    def _get_listening_ports(self):
        """Get listening ports"""
        try:
            ports = []
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN":
                    ports.append(
                        {
                            "port": conn.laddr.port,
                            "address": conn.laddr.ip,
                            "pid": conn.pid,
                        }
                    )
            return ports
        except:
            return []

    def _get_nginx_processes(self):
        """Get nginx process information"""
        try:
            processes = []
            for proc in psutil.process_iter(
                ["pid", "name", "cmdline", "memory_info", "cpu_percent"]
            ):
                if proc.info["name"] == "nginx":
                    processes.append(
                        {
                            "pid": proc.info["pid"],
                            "cmdline": (
                                " ".join(proc.info["cmdline"])
                                if proc.info["cmdline"]
                                else ""
                            ),
                            "memory_mb": proc.info["memory_info"].rss / 1024 / 1024,
                            "cpu_percent": proc.info["cpu_percent"],
                        }
                    )
            return processes
        except:
            return []

    def _get_active_connections(self):
        """Get active network connections"""
        try:
            connections = []
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "ESTABLISHED":
                    connections.append(
                        {
                            "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "remote_address": (
                                f"{conn.raddr.ip}:{conn.raddr.port}"
                                if conn.raddr
                                else None
                            ),
                            "status": conn.status,
                            "pid": conn.pid,
                        }
                    )
            return connections
        except:
            return []

    def _get_dns_info(self):
        """Get DNS information"""
        try:
            dns_info = {}

            # Try to read /etc/resolv.conf
            try:
                with open("/etc/resolv.conf", "r") as f:
                    dns_info["resolv_conf"] = f.read().strip()
            except:
                dns_info["resolv_conf"] = "Could not read /etc/resolv.conf"

            # Test DNS resolution
            try:
                import socket

                result = socket.gethostbyname("google.com")
                dns_info["dns_working"] = True
                dns_info["test_resolution"] = result
            except:
                dns_info["dns_working"] = False

            return dns_info
        except:
            return {}

    def _get_server_ip_addresses(self):
        """Get server IP addresses"""
        try:
            addresses = []
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        addresses.append(
                            {
                                "interface": interface,
                                "ip": addr.address,
                                "netmask": addr.netmask,
                            }
                        )
            return addresses
        except:
            return []

    def _get_system_uptime(self):
        """Get system uptime"""
        try:
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            return {
                "boot_time": boot_time.isoformat(),
                "uptime_seconds": uptime.total_seconds(),
                "uptime_human": str(uptime),
            }
        except:
            return {}


def register_nginx_routes(app, deps):
    """Register nginx information routes including domain availability checking"""
    nginx_service = NginxService(deps)

    @app.route("/api/nginx/status", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_nginx_status():
        nginx_info = nginx_service.get_comprehensive_status()
        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "nginx": nginx_info,
            }
        )

    @app.route("/api/nginx/sites-enabled", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_nginx_enabled_sites():
        enabled_sites = nginx_service.get_enabled_sites()
        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "enabled_sites": enabled_sites,
                "count": len(enabled_sites),
            }
        )

    @app.route("/api/sites", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_all_sites_detailed():
        sites_info = nginx_service.get_comprehensive_sites_info()
        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "server_info": nginx_service.get_server_info(),
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
                        [s for s in sites_info if s.get("site_type") == "static"]
                    ),
                    "dynamic_sites": len(
                        [s for s in sites_info if s.get("site_type") != "static"]
                    ),
                },
            }
        )

    @app.route("/api/sites/<domain_name>/details", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_site_details(domain_name):
        site_info = nginx_service.get_site_detailed_info(domain_name)
        if not site_info:
            return APIResponse.not_found("Site not found")
        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "site": site_info,
            }
        )

    @app.route("/api/sites/<domain_name>/nginx-config", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_site_nginx_config(domain_name):
        config_content = nginx_service.get_nginx_config_content(domain_name)
        config_info = nginx_service.get_nginx_config_info(domain_name)
        if not config_content:
            return APIResponse.not_found("Nginx config not found")
        return APIResponse.success(
            {
                "domain_name": domain_name,
                "config_info": config_info,
                "config_content": config_content,
                "parsed_config": nginx_service.parse_nginx_config_content(
                    config_content
                ),
            }
        )

    @app.route("/api/sites/connectivity", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def test_sites_connectivity():
        connectivity_results = nginx_service.test_all_sites_connectivity()
        return APIResponse.success(
            {
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

    @app.route("/api/server/network-info", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_server_network_info():
        network_info = nginx_service.get_comprehensive_network_info()
        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "network": network_info,
            }
        )

    # NEW ROUTE: Check domain in nginx only
    @app.route("/api/nginx/check-domain", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def check_domain_in_nginx():
        """Check if domain exists in nginx configurations only"""
        try:
            data = request.json
            if not data or not data.get("domain"):
                return APIResponse.bad_request("Domain required")

            domain_name = data["domain"].lower().strip()

            # Use nginx service to check domain
            nginx_results = nginx_service.check_domain_availability_in_nginx(
                domain_name
            )
            exists, locations = nginx_service.is_domain_in_nginx(domain_name)

            return APIResponse.success(
                {
                    "domain": domain_name,
                    "exists_in_nginx": exists,
                    "locations": locations,
                    "details": nginx_results,
                    "timestamp": datetime.now().isoformat(),
                }
            )

        except Exception as e:
            deps["logger"].error(f"Nginx domain check failed: {e}")
            return APIResponse.server_error(f"Nginx check failed: {str(e)}")
