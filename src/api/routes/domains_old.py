# src/api/routes/domains.py
"""
API routes for dynamic domain and subdomain management with full CRUD operations
Supports dynamic parent domain creation and complete subdomain lifecycle management
"""

import json
import shutil
import subprocess
import glob
import os
import socket
import re
import functools
import sqlite3
from flask import request, jsonify
from datetime import datetime
from .ssl_manager import create_ssl_manager


def allocate_port_for_deployment(preferred_port=None, start_range=3001, end_range=4000):
    """Allocate an available port for deployment"""

    def is_port_available(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(("localhost", port))
                return result != 0
        except:
            return False

    # Try preferred port first
    if preferred_port and start_range <= preferred_port <= end_range:
        if is_port_available(preferred_port):
            return preferred_port

    # Find first available port in range
    for port in range(start_range, end_range + 1):
        if is_port_available(port):
            return port

    raise Exception("No available ports in range")


def cleanup_pm2_processes_for_domain(domain_name, logger):
    """Cleanup PM2 processes for a domain"""
    stopped_processes = []
    errors = []

    try:
        result = subprocess.run(["pm2", "jlist"], capture_output=True, text=True)
        if result.returncode != 0:
            return {
                "stopped_processes": [],
                "errors": ["PM2 not available"],
                "total_stopped": 0,
            }

        pm2_data = json.loads(result.stdout)
        domain_parts = domain_name.split(".")

        matching_processes = []
        for process in pm2_data:
            process_name = process.get("name", "")
            if (
                process_name == domain_name
                or (len(domain_parts) > 1 and process_name == domain_parts[0])
                or domain_name in process_name
            ):
                matching_processes.append(process)

        for process in matching_processes:
            process_name = process.get("name")
            try:
                stop_result = subprocess.run(
                    ["pm2", "stop", process_name], capture_output=True, text=True
                )

                if stop_result.returncode == 0:
                    delete_result = subprocess.run(
                        ["pm2", "delete", process_name], capture_output=True, text=True
                    )

                    stopped_processes.append(
                        {
                            "name": process_name,
                            "pid": process.get("pid"),
                            "status": (
                                "stopped_and_deleted"
                                if delete_result.returncode == 0
                                else "stopped"
                            ),
                        }
                    )
                    logger.info(f"Stopped and removed PM2 process: {process_name}")
                else:
                    errors.append(f"Failed to stop PM2 process {process_name}")

            except Exception as e:
                errors.append(f"Error stopping PM2 process {process_name}: {str(e)}")

        return {
            "stopped_processes": stopped_processes,
            "errors": errors,
            "total_stopped": len(stopped_processes),
        }

    except Exception as e:
        return {
            "stopped_processes": [],
            "errors": [f"PM2 cleanup failed: {str(e)}"],
            "total_stopped": 0,
        }


def cleanup_nginx_config(domain_name, logger):
    """Remove nginx configuration files for domain"""
    removed_files = []
    errors = []
    try:
        nginx_files = [
            f"/etc/nginx/sites-available/{domain_name}",
            f"/etc/nginx/sites-enabled/{domain_name}",
        ]
        for nginx_file in nginx_files:
            if os.path.exists(nginx_file):
                try:
                    if os.path.islink(nginx_file):
                        os.unlink(nginx_file)  # Remove symlink
                    else:
                        os.remove(nginx_file)  # Remove regular file
                    removed_files.append(nginx_file)
                    logger.info(f"Removed nginx config: {nginx_file}")
                except Exception as e:
                    errors.append(f"Failed to remove {nginx_file}: {str(e)}")
                    logger.error(f"Failed to remove nginx config {nginx_file}: {e}")
        # Test and reload nginx configuration
        try:
            test_result = subprocess.run(
                ["nginx", "-t"], capture_output=True, text=True, timeout=10
            )
            if test_result.returncode == 0:
                reload_result = subprocess.run(
                    ["systemctl", "reload", "nginx"], capture_output=True, timeout=30
                )
                if reload_result.returncode != 0:
                    errors.append("Failed to reload nginx after cleanup")
            else:
                errors.append(f"Nginx config test failed: {test_result.stderr}")
        except Exception as e:
            errors.append(f"Nginx reload error: {str(e)}")

        return {
            "removed_files": removed_files,
            "errors": errors,
            "success": len(errors) == 0,
        }

    except Exception as e:
        logger.error(f"Nginx cleanup error for {domain_name}: {e}")
        return {
            "removed_files": [],
            "errors": [f"Nginx cleanup failed: {str(e)}"],
            "success": False,
        }


def cleanup_application_files(domain_name, logger):
    """Remove application files and directories for domain"""
    removed_files = []
    errors = []
    try:
        # Application directories to check
        app_directories = [
            f"/tmp/www/domains/{domain_name}",
            f"/tmp/www/domains/{domain_name.replace('.', '-')}",
            f"/opt/hosting-manager/apps/{domain_name}",
            f"/var/www/{domain_name}",
        ]
        # Add subdomain-specific directories
        domain_parts = domain_name.split(".")
        if len(domain_parts) > 1:
            subdomain = domain_parts[0]
            app_directories.extend(
                [
                    f"/tmp/www/domains/{subdomain}",
                    f"/opt/hosting-manager/apps/{subdomain}",
                    f"/var/www/{subdomain}",
                ]
            )

        for app_dir in app_directories:
            if os.path.exists(app_dir) and os.path.isdir(app_dir):
                try:
                    # Calculate directory size for logging
                    try:
                        dir_size = sum(
                            os.path.getsize(os.path.join(dirpath, filename))
                            for dirpath, dirnames, filenames in os.walk(app_dir)
                            for filename in filenames
                        )
                        dir_size_mb = dir_size / (1024 * 1024)
                    except:
                        dir_size_mb = 0

                    shutil.rmtree(app_dir)
                    removed_files.append(f"{app_dir} ({dir_size_mb:.1f}MB)")
                    logger.info(f"Removed app directory: {app_dir}")

                except Exception as e:
                    errors.append(f"Failed to remove directory {app_dir}: {str(e)}")

        # Remove log files
        log_patterns = [
            f"/tmp/process-logs/{domain_name}*.log",
            f"/tmp/process-logs/{domain_parts[0] if len(domain_parts) > 1 else domain_name}*.log",
            f"/var/log/nginx/{domain_name}*.log",
            f"/tmp/hosting/logs/{domain_name}*.log",
        ]

        for pattern in log_patterns:
            try:
                log_files = glob.glob(pattern)
                for log_file in log_files:
                    if os.path.exists(log_file):
                        os.remove(log_file)
                        removed_files.append(log_file)
                        logger.info(f"Removed log file: {log_file}")
            except Exception as e:
                errors.append(f"Failed to remove logs matching {pattern}: {str(e)}")

        # Remove SSL certificates
        ssl_dirs = [
            f"/etc/letsencrypt/live/{domain_name}",
            f"/etc/letsencrypt/archive/{domain_name}",
            f"/etc/letsencrypt/renewal/{domain_name}.conf",
        ]

        for ssl_path in ssl_dirs:
            if os.path.exists(ssl_path):
                try:
                    if os.path.isdir(ssl_path):
                        shutil.rmtree(ssl_path)
                    else:
                        os.remove(ssl_path)
                    removed_files.append(ssl_path)
                    logger.info(f"Removed SSL files: {ssl_path}")
                except Exception as e:
                    errors.append(f"Failed to remove SSL files {ssl_path}: {str(e)}")

        return {
            "removed_files": removed_files,
            "errors": errors,
            "success": len(errors) == 0,
        }

    except Exception as e:
        logger.error(f"File cleanup error for {domain_name}: {e}")
        return {
            "removed_files": [],
            "errors": [f"File cleanup failed: {str(e)}"],
            "success": False,
        }


class DomainManager:
    """Dynamic domain management with database storage"""

    def __init__(self, hosting_manager, logger):
        self.hosting_manager = hosting_manager
        self.logger = logger
        self._setup_parent_domains_table()

    def _setup_parent_domains_table(self):
        """Create parent domains table if it doesn't exist"""
        try:
            conn = self.hosting_manager.get_database_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS parent_domains (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain_name TEXT UNIQUE NOT NULL,
                        port_range_start INTEGER NOT NULL DEFAULT 3001,
                        port_range_end INTEGER NOT NULL DEFAULT 3100,
                        ssl_enabled BOOLEAN DEFAULT 1,
                        description TEXT,
                        status TEXT DEFAULT 'active',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """
                )

                # Create index for better performance
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_parent_domains_name ON parent_domains(domain_name)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_parent_domains_status ON parent_domains(status)"
                )

                conn.commit()
                conn.close()
                self.logger.info("Parent domains table ready")
        except Exception as e:
            self.logger.error(f"Failed to setup parent domains table: {e}")

    def add_parent_domain(
        self,
        domain_name,
        port_range_start=None,
        port_range_end=None,
        description="",
        ssl_enabled=True,
    ):
        """Add a new parent domain"""
        try:
            # Validate domain format
            if not self._is_valid_domain(domain_name):
                return False, "Invalid domain format"

            # Auto-assign port range if not provided
            if not port_range_start or not port_range_end:
                port_range_start, port_range_end = self._get_next_port_range()

            conn = self.hosting_manager.get_database_connection()
            if not conn:
                return False, "Database connection failed"

            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO parent_domains 
                (domain_name, port_range_start, port_range_end, description, ssl_enabled)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    domain_name,
                    port_range_start,
                    port_range_end,
                    description,
                    ssl_enabled,
                ),
            )

            conn.commit()
            conn.close()

            self.logger.info(
                f"Added parent domain: {domain_name} [{port_range_start}-{port_range_end}]"
            )
            return True, f"Domain {domain_name} added successfully"

        except sqlite3.IntegrityError:
            return False, f"Domain {domain_name} already exists"
        except Exception as e:
            self.logger.error(f"Failed to add parent domain {domain_name}: {e}")
            return False, f"Failed to add domain: {str(e)}"

    def get_all_parent_domains(self):
        """Get all parent domains from database"""
        try:
            conn = self.hosting_manager.get_database_connection()
            if not conn:
                return []

            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT domain_name, port_range_start, port_range_end, 
                       description, ssl_enabled, status, created_at
                FROM parent_domains 
                WHERE status = 'active'
                ORDER BY created_at ASC
            """
            )

            domains = []
            for row in cursor.fetchall():
                # Get subdomain count
                subdomain_count = self._get_subdomain_count(row[0])

                domain_info = {
                    "id": row[0],
                    "name": row[0],
                    "domain": row[0],
                    "port_range": [row[1], row[2]],
                    "port_range_start": row[1],
                    "port_range_end": row[2],
                    "description": row[3] or f"{row[0]} domain",
                    "ssl_enabled": bool(row[4]),
                    "status": row[5],
                    "created_at": row[6],
                    "current_subdomains": subdomain_count,
                    "available_ports": (row[2] - row[1] + 1) - subdomain_count,
                    "example_subdomain": f"myapp.{row[0]}",
                }
                domains.append(domain_info)

            conn.close()
            return domains

        except Exception as e:
            self.logger.error(f"Failed to get parent domains: {e}")
            return []

    def get_parent_domain_info(self, domain_name):
        """Get specific parent domain info"""
        try:
            conn = self.hosting_manager.get_database_connection()
            if not conn:
                return None

            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT domain_name, port_range_start, port_range_end, 
                       description, ssl_enabled, status, created_at, updated_at
                FROM parent_domains 
                WHERE domain_name = ? AND status = 'active'
            """,
                (domain_name,),
            )

            row = cursor.fetchone()
            if not row:
                conn.close()
                return None

            subdomain_count = self._get_subdomain_count(row[0])

            domain_info = {
                "domain_name": row[0],
                "port_range_start": row[1],
                "port_range_end": row[2],
                "port_range": [row[1], row[2]],
                "description": row[3],
                "ssl_enabled": bool(row[4]),
                "status": row[5],
                "created_at": row[6],
                "updated_at": row[7],
                "current_subdomains": subdomain_count,
                "available_ports": (row[2] - row[1] + 1) - subdomain_count,
            }

            conn.close()
            return domain_info

        except Exception as e:
            self.logger.error(
                f"Failed to get parent domain info for {domain_name}: {e}"
            )
            return None

    def update_parent_domain(self, domain_name, **kwargs):
        """Update parent domain properties"""
        try:
            conn = self.hosting_manager.get_database_connection()
            if not conn:
                return False, "Database connection failed"

            # Build update query dynamically
            update_fields = []
            values = []

            allowed_fields = [
                "port_range_start",
                "port_range_end",
                "description",
                "ssl_enabled",
            ]
            for field in allowed_fields:
                if field in kwargs:
                    update_fields.append(f"{field} = ?")
                    values.append(kwargs[field])

            if not update_fields:
                return False, "No valid fields to update"

            values.append(domain_name)

            cursor = conn.cursor()
            cursor.execute(
                f"""
                UPDATE parent_domains 
                SET {', '.join(update_fields)}, updated_at = CURRENT_TIMESTAMP
                WHERE domain_name = ?
            """,
                values,
            )

            if cursor.rowcount == 0:
                conn.close()
                return False, f"Domain {domain_name} not found"

            conn.commit()
            conn.close()

            self.logger.info(f"Updated parent domain: {domain_name}")
            return True, f"Domain {domain_name} updated successfully"

        except Exception as e:
            self.logger.error(f"Failed to update parent domain {domain_name}: {e}")
            return False, f"Failed to update domain: {str(e)}"

    def delete_parent_domain(self, domain_name, force=False):
        """Delete parent domain (only if no subdomains exist or force=True)"""
        try:
            # Check for existing subdomains
            subdomain_count = self._get_subdomain_count(domain_name)

            if subdomain_count > 0 and not force:
                return (
                    False,
                    f"Cannot delete domain with {subdomain_count} active subdomains. Use force=true to delete anyway.",
                )

            conn = self.hosting_manager.get_database_connection()
            if not conn:
                return False, "Database connection failed"

            cursor = conn.cursor()

            if force and subdomain_count > 0:
                # Delete all subdomains first
                cursor.execute(
                    "SELECT domain_name FROM domains WHERE domain_name LIKE ?",
                    (f"%.{domain_name}",),
                )
                subdomains = cursor.fetchall()

                for subdomain_row in subdomains:
                    subdomain = subdomain_row[0]
                    # Cleanup subdomain completely
                    self._cleanup_subdomain_completely(subdomain)

            # Mark parent domain as deleted
            cursor.execute(
                "UPDATE parent_domains SET status = 'deleted', updated_at = CURRENT_TIMESTAMP WHERE domain_name = ?",
                (domain_name,),
            )

            if cursor.rowcount == 0:
                conn.close()
                return False, f"Domain {domain_name} not found"

            conn.commit()
            conn.close()

            self.logger.info(f"Deleted parent domain: {domain_name} (force: {force})")
            return True, f"Domain {domain_name} deleted successfully"

        except Exception as e:
            self.logger.error(f"Failed to delete parent domain {domain_name}: {e}")
            return False, f"Failed to delete domain: {str(e)}"

    def get_port_range_for_domain(self, domain_name):
        """Get port range for a specific parent domain"""
        try:
            conn = self.hosting_manager.get_database_connection()
            if not conn:
                return None

            cursor = conn.cursor()
            cursor.execute(
                "SELECT port_range_start, port_range_end FROM parent_domains WHERE domain_name = ? AND status = 'active'",
                (domain_name,),
            )

            row = cursor.fetchone()
            conn.close()

            if row:
                return [row[0], row[1]]
            return None

        except Exception as e:
            self.logger.error(f"Failed to get port range for {domain_name}: {e}")
            return None

    def _get_subdomain_count(self, parent_domain):
        """Get count of subdomains for a parent domain"""
        try:
            all_domains = self.hosting_manager.list_domains()
            return len(
                [
                    d
                    for d in all_domains
                    if d.get("domain_name", "").endswith(f".{parent_domain}")
                    and d.get("status") == "active"
                ]
            )
        except:
            return 0

    def _get_next_port_range(self):
        """Auto-assign next available port range"""
        try:
            conn = self.hosting_manager.get_database_connection()
            if not conn:
                return 3001, 3100

            cursor = conn.cursor()
            cursor.execute(
                "SELECT MAX(port_range_end) FROM parent_domains WHERE status = 'active'"
            )

            row = cursor.fetchone()
            conn.close()

            if row and row[0]:
                next_start = row[0] + 1
                return next_start, next_start + 99
            else:
                return 3001, 3100

        except Exception as e:
            self.logger.error(f"Failed to get next port range: {e}")
            return 3001, 3100

    def _is_valid_domain(self, domain):
        """Validate domain format"""
        if not domain or len(domain) > 253:
            return False

        # Basic domain regex
        pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
        return re.match(pattern, domain) is not None

    def _cleanup_subdomain_completely(self, subdomain):
        """Complete cleanup of a subdomain"""
        try:
            # Stop processes
            cleanup_pm2_processes_for_domain(subdomain, self.logger)

            # Remove nginx config
            cleanup_nginx_config(subdomain, self.logger)

            # Remove files
            cleanup_application_files(subdomain, self.logger)

            # Remove from database
            self.hosting_manager.remove_domain(subdomain)

        except Exception as e:
            self.logger.error(f"Failed complete cleanup for {subdomain}: {e}")


class DomainValidator:
    """Domain validation utilities"""

    @staticmethod
    def _is_valid_subdomain(subdomain):
        """Validate subdomain format"""
        if not subdomain or len(subdomain) > 63:
            return False

        if not (subdomain[0].isalnum() and subdomain[-1].isalnum()):
            return False

        if "--" in subdomain:
            return False

        if not re.match(r"^[a-zA-Z0-9-]+$", subdomain):
            return False

        reserved = ["www", "mail", "ftp", "localhost", "api", "admin", "root", "test"]
        if subdomain.lower() in reserved:
            return False

        return True


class PreDeploymentValidator:
    """Comprehensive validation before any subdomain deployment"""

    def __init__(self, deps):
        self.config = deps["config"]
        self.logger = deps["logger"]
        self.hosting_manager = deps["hosting_manager"]

    def validate_domain_for_deployment(self, domain_name):
        """
        Comprehensive validation of domain before deployment
        Returns: (is_valid, validation_results)
        """
        validation_results = {
            "domain": domain_name,
            "is_available": True,
            "conflicts": [],
            "checks": {
                "database": {"exists": False, "details": None},
                "nginx_available": {"exists": False, "details": None},
                "nginx_enabled": {"exists": False, "details": None},
                "filesystem": {"exists": False, "details": None},
                "processes": {"exists": False, "details": None},
            },
            "timestamp": datetime.now().isoformat(),
        }

        try:
            # 1. Database check - most critical
            self._check_database(domain_name, validation_results)

            # 2. Nginx configuration checks
            self._check_nginx_available(domain_name, validation_results)
            self._check_nginx_enabled(domain_name, validation_results)

            # 3. Filesystem check
            self._check_filesystem(domain_name, validation_results)

            # 4. Process check (PM2/systemd)
            self._check_processes(domain_name, validation_results)

            # 5. Determine overall availability
            validation_results["is_available"] = (
                len(validation_results["conflicts"]) == 0
            )

            return validation_results["is_available"], validation_results

        except Exception as e:
            self.logger.error(
                f"Pre-deployment validation failed for {domain_name}: {e}"
            )
            validation_results["is_available"] = False
            validation_results["conflicts"].append(
                {
                    "source": "validation_system",
                    "type": "system_error",
                    "message": f"Validation system error: {str(e)}",
                }
            )
            return False, validation_results

    def _check_database(self, domain_name, results):
        """Check if domain exists in database"""
        try:
            conn = self.hosting_manager.get_database_connection()
            if not conn:
                results["conflicts"].append(
                    {
                        "source": "database",
                        "type": "connection_error",
                        "message": "Could not connect to database",
                    }
                )
                return

            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT domain_name, port, site_type, status, created_at, updated_at 
                FROM domains 
                WHERE domain_name = ?
            """,
                (domain_name,),
            )

            row = cursor.fetchone()
            conn.close()

            if row:
                results["checks"]["database"]["exists"] = True
                results["checks"]["database"]["details"] = {
                    "domain_name": row[0],
                    "port": row[1],
                    "site_type": row[2],
                    "status": row[3],
                    "created_at": row[4],
                    "updated_at": row[5],
                }

                results["conflicts"].append(
                    {
                        "source": "database",
                        "type": "domain_exists",
                        "message": f"Domain {domain_name} already exists in database",
                        "details": {
                            "status": row[3],
                            "port": row[1],
                            "created": row[4],
                        },
                    }
                )

                self.logger.info(
                    f"Database conflict: {domain_name} exists with status {row[3]}"
                )
            else:
                self.logger.debug(f"Database check passed: {domain_name} not found")

        except Exception as e:
            self.logger.error(f"Database check failed for {domain_name}: {e}")
            results["conflicts"].append(
                {
                    "source": "database",
                    "type": "check_error",
                    "message": f"Database check failed: {str(e)}",
                }
            )

    def _check_nginx_available(self, domain_name, results):
        """Check if nginx config exists in sites-available"""
        try:
            sites_available_dir = self.config.get(
                "nginx_sites_dir", "/etc/nginx/sites-available"
            )
            config_path = os.path.join(sites_available_dir, domain_name)

            if os.path.exists(config_path):
                results["checks"]["nginx_available"]["exists"] = True

                # Get file details
                stat_info = os.stat(config_path)
                file_size = stat_info.st_size
                modified_time = datetime.fromtimestamp(stat_info.st_mtime).isoformat()

                results["checks"]["nginx_available"]["details"] = {
                    "path": config_path,
                    "size": file_size,
                    "modified": modified_time,
                    "is_symlink": os.path.islink(config_path),
                }

                results["conflicts"].append(
                    {
                        "source": "nginx_available",
                        "type": "config_exists",
                        "message": f"Nginx config already exists: {config_path}",
                        "details": {
                            "path": config_path,
                            "size": file_size,
                            "modified": modified_time,
                        },
                    }
                )

                self.logger.info(f"Nginx available conflict: {config_path} exists")
            else:
                self.logger.debug(
                    f"Nginx available check passed: {config_path} not found"
                )

        except Exception as e:
            self.logger.error(f"Nginx available check failed for {domain_name}: {e}")
            results["conflicts"].append(
                {
                    "source": "nginx_available",
                    "type": "check_error",
                    "message": f"Nginx available check failed: {str(e)}",
                }
            )

    def _check_nginx_enabled(self, domain_name, results):
        """Check if nginx config exists in sites-enabled"""
        try:
            sites_enabled_dir = self.config.get(
                "nginx_enabled_dir", "/etc/nginx/sites-enabled"
            )
            enabled_path = os.path.join(sites_enabled_dir, domain_name)

            if os.path.exists(enabled_path):
                results["checks"]["nginx_enabled"]["exists"] = True

                # Get file/symlink details
                stat_info = os.stat(enabled_path)
                is_symlink = os.path.islink(enabled_path)

                details = {
                    "path": enabled_path,
                    "size": stat_info.st_size,
                    "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                    "is_symlink": is_symlink,
                }

                if is_symlink:
                    try:
                        details["target"] = os.readlink(enabled_path)
                        # Check if target exists
                        details["target_exists"] = os.path.exists(details["target"])
                    except Exception as e:
                        details["symlink_error"] = str(e)

                results["checks"]["nginx_enabled"]["details"] = details

                results["conflicts"].append(
                    {
                        "source": "nginx_enabled",
                        "type": "config_enabled",
                        "message": f"Nginx config already enabled: {enabled_path}",
                        "details": details,
                    }
                )

                self.logger.info(f"Nginx enabled conflict: {enabled_path} exists")
            else:
                self.logger.debug(
                    f"Nginx enabled check passed: {enabled_path} not found"
                )

        except Exception as e:
            self.logger.error(f"Nginx enabled check failed for {domain_name}: {e}")
            results["conflicts"].append(
                {
                    "source": "nginx_enabled",
                    "type": "check_error",
                    "message": f"Nginx enabled check failed: {str(e)}",
                }
            )

    def _check_filesystem(self, domain_name, results):
        """Check if domain directory exists in filesystem"""
        try:
            web_root = self.config.get("web_root", "/tmp/www/domains")
            domain_path = os.path.join(web_root, domain_name)

            if os.path.exists(domain_path):
                results["checks"]["filesystem"]["exists"] = True

                # Get directory details
                try:
                    file_count = len(os.listdir(domain_path))
                    dir_size = self._get_directory_size(domain_path)
                    stat_info = os.stat(domain_path)

                    details = {
                        "path": domain_path,
                        "file_count": file_count,
                        "size_bytes": dir_size,
                        "modified": datetime.fromtimestamp(
                            stat_info.st_mtime
                        ).isoformat(),
                    }

                    results["checks"]["filesystem"]["details"] = details

                    results["conflicts"].append(
                        {
                            "source": "filesystem",
                            "type": "directory_exists",
                            "message": f"Domain directory already exists: {domain_path}",
                            "details": details,
                        }
                    )

                    self.logger.info(
                        f"Filesystem conflict: {domain_path} exists with {file_count} files"
                    )
                except Exception as e:
                    results["conflicts"].append(
                        {
                            "source": "filesystem",
                            "type": "directory_exists",
                            "message": f"Domain directory exists but cannot read details: {domain_path}",
                            "details": {"error": str(e)},
                        }
                    )
            else:
                self.logger.debug(f"Filesystem check passed: {domain_path} not found")

        except Exception as e:
            self.logger.error(f"Filesystem check failed for {domain_name}: {e}")
            results["conflicts"].append(
                {
                    "source": "filesystem",
                    "type": "check_error",
                    "message": f"Filesystem check failed: {str(e)}",
                }
            )

    def _check_processes(self, domain_name, results):
        """Check if processes are running for this domain"""
        try:
            # Check PM2 processes
            pm2_processes = self._check_pm2_processes(domain_name)

            # Check systemd services
            systemd_services = self._check_systemd_services(domain_name)

            all_processes = pm2_processes + systemd_services

            if all_processes:
                results["checks"]["processes"]["exists"] = True
                results["checks"]["processes"]["details"] = {
                    "pm2_processes": pm2_processes,
                    "systemd_services": systemd_services,
                    "total_count": len(all_processes),
                }

                results["conflicts"].append(
                    {
                        "source": "processes",
                        "type": "processes_running",
                        "message": f"Processes already running for domain: {domain_name}",
                        "details": {
                            "process_count": len(all_processes),
                            "processes": all_processes,
                        },
                    }
                )

                self.logger.info(
                    f"Process conflict: {len(all_processes)} processes running for {domain_name}"
                )
            else:
                self.logger.debug(
                    f"Process check passed: no processes found for {domain_name}"
                )

        except Exception as e:
            self.logger.error(f"Process check failed for {domain_name}: {e}")
            results["conflicts"].append(
                {
                    "source": "processes",
                    "type": "check_error",
                    "message": f"Process check failed: {str(e)}",
                }
            )

    def _check_pm2_processes(self, domain_name):
        """Check PM2 for processes matching domain"""
        try:
            result = subprocess.run(
                ["pm2", "jlist"], capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0:
                return []

            pm2_data = json.loads(result.stdout)
            matching_processes = []

            # Extract subdomain part for matching
            subdomain_part = (
                domain_name.split(".")[0] if "." in domain_name else domain_name
            )

            for process in pm2_data:
                process_name = process.get("name", "")

                # Match by exact name or subdomain
                if (
                    process_name == domain_name
                    or process_name == subdomain_part
                    or domain_name in process_name
                ):

                    matching_processes.append(
                        {
                            "name": process_name,
                            "pid": process.get("pid"),
                            "status": process.get("pm2_env", {}).get("status"),
                            "manager": "pm2",
                        }
                    )

            return matching_processes

        except Exception as e:
            self.logger.warning(f"PM2 process check failed: {e}")
            return []

    def _check_systemd_services(self, domain_name):
        """Check systemd for services matching domain"""
        try:
            # Extract subdomain part
            subdomain_part = (
                domain_name.split(".")[0] if "." in domain_name else domain_name
            )

            # Check for nodejs-{subdomain} service
            service_name = f"nodejs-{subdomain_part}"

            result = subprocess.run(
                ["systemctl", "is-active", service_name],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:  # Service is active
                return [
                    {"name": service_name, "status": "active", "manager": "systemd"}
                ]
            else:
                return []

        except Exception as e:
            self.logger.warning(f"Systemd service check failed: {e}")
            return []

    def _get_directory_size(self, path):
        """Get directory size recursively"""
        try:
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                    except (OSError, IOError):
                        continue
            return total_size
        except Exception:
            return 0

    def format_validation_error_message(self, validation_results):
        """Format user-friendly error message from validation results"""
        domain = validation_results["domain"]
        conflicts = validation_results["conflicts"]

        if not conflicts:
            return f"Domain {domain} is available for deployment"

        message_parts = [
            f"Domain {domain} cannot be deployed due to existing conflicts:"
        ]

        for conflict in conflicts:
            source = conflict["source"]
            conflict_type = conflict["type"]
            details = conflict.get("details", {})

            if source == "database":
                if conflict_type == "domain_exists":
                    status = details.get("status", "unknown")
                    port = details.get("port", "unknown")
                    created = details.get("created", "unknown")
                    message_parts.append(
                        f"  • Database: Domain exists (Status: {status}, Port: {port}, Created: {created})"
                    )

            elif source == "nginx_available":
                if conflict_type == "config_exists":
                    path = details.get("path", "unknown")
                    size = details.get("size", 0)
                    message_parts.append(
                        f"  • Nginx Config: Configuration file exists ({path}, {size} bytes)"
                    )

            elif source == "nginx_enabled":
                if conflict_type == "config_enabled":
                    path = details.get("path", "unknown")
                    message_parts.append(
                        f"  • Nginx Enabled: Site is actively configured ({path})"
                    )

            elif source == "filesystem":
                if conflict_type == "directory_exists":
                    path = details.get("path", "unknown")
                    file_count = details.get("file_count", 0)
                    message_parts.append(
                        f"  • Files: Domain directory exists ({path}, {file_count} files)"
                    )

            elif source == "processes":
                if conflict_type == "processes_running":
                    process_count = details.get("process_count", 0)
                    message_parts.append(
                        f"  • Processes: {process_count} active processes found"
                    )

        message_parts.append("")
        message_parts.append(
            "Please clean up existing resources before deploying, or use the cleanup endpoint:"
        )
        message_parts.append(f"POST /api/domains/{domain}/cleanup")

        return "\n".join(message_parts)


def _check_domain_comprehensive(deps, domain_name):
    """Use the comprehensive domain checker from nginx service"""
    try:
        # Get comprehensive check using the nginx routes directly instead of importing NginxService
        import requests
        import json

        # Make internal API call to the working nginx endpoint
        try:
            base_url = "http://localhost:5000"  # or get from config
            response = requests.post(
                f"{base_url}/api/nginx/check-domain",
                json={"domain": domain_name},
                timeout=5,
            )

            if response.status_code == 200:
                nginx_data = response.json()
                nginx_results = {
                    "nginx_available": {
                        "available": not nginx_data.get("exists_in_nginx", False),
                        "details": nginx_data.get("details", {}),
                        "message": "",
                    },
                    "nginx_enabled": {
                        "available": True,
                        "details": {},
                        "message": "",
                    },  # nginx endpoint checks both
                }
            else:
                # Fallback if API call fails
                nginx_results = {
                    "nginx_available": {
                        "available": True,
                        "details": {},
                        "message": "Nginx check via API failed",
                    },
                    "nginx_enabled": {
                        "available": True,
                        "details": {},
                        "message": "Nginx check via API failed",
                    },
                }
        except Exception as e:
            deps["logger"].warning(f"Internal nginx API call failed: {e}")
            nginx_results = {
                "nginx_available": {
                    "available": True,
                    "details": {},
                    "message": "Nginx check unavailable",
                },
                "nginx_enabled": {
                    "available": True,
                    "details": {},
                    "message": "Nginx check unavailable",
                },
            }

        # Add database check
        results = {"database": {"available": True, "details": {}, "message": ""}}

        try:
            hosting_manager = deps["hosting_manager"]
            conn = hosting_manager.get_database_connection()

            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COUNT(*), port, site_type, created_at, status FROM domains WHERE domain_name = ?",
                    (domain_name,),
                )

                result = cursor.fetchone()
                count = result[0] if result else 0

                if count > 0 and result:
                    results["database"]["available"] = False
                    results["database"]["details"] = {
                        "port": result[1],
                        "site_type": result[2],
                        "created_at": result[3],
                        "status": result[4],
                    }
                    results["database"][
                        "message"
                    ] = f"Domain found in database with status: {result[4]}"

                conn.close()

        except Exception as e:
            deps["logger"].error(f"Database check failed: {e}")
            results["database"]["message"] = f"Database check failed: {str(e)}"

        # Combine nginx and database results
        results.update(nginx_results)
        return results

    except Exception as e:
        deps["logger"].error(f"Comprehensive domain check failed: {e}")
        # Fallback to basic database check only
        return {
            "database": {
                "available": True,
                "details": {},
                "message": f"Check failed: {str(e)}",
            },
            "nginx_available": {
                "available": True,
                "details": {},
                "message": "Check skipped due to error",
            },
            "nginx_enabled": {
                "available": True,
                "details": {},
                "message": "Check skipped due to error",
            },
        }


def register_domain_routes(app, deps):
    """Register dynamic domain management routes with full CRUD operations"""

    # Import utilities
    try:
        from ..utils import APIResponse, handle_api_errors
    except ImportError:
        # Fallback utilities
        class APIResponse:
            @staticmethod
            def success(data):
                return jsonify({"success": True, **data})

            @staticmethod
            def bad_request(message):
                if isinstance(message, dict):
                    return jsonify({"success": False, **message}), 400
                return jsonify({"success": False, "error": message}), 400

            @staticmethod
            def server_error(message, details=None):
                response = {"success": False, "error": message}
                if details:
                    response["details"] = details
                return jsonify(response), 500

            @staticmethod
            def not_found(message):
                return jsonify({"success": False, "error": message}), 404

        def handle_api_errors(logger):
            def decorator(f):
                @functools.wraps(f)
                def wrapper(*args, **kwargs):
                    try:
                        return f(*args, **kwargs)
                    except Exception as e:
                        logger.error(f"API error in {f.__name__}: {e}")
                        return jsonify({"success": False, "error": str(e)}), 500

                return wrapper

            return decorator

    # Initialize domain manager
    domain_manager = DomainManager(deps["hosting_manager"], deps["logger"])

    # ===============================================================================
    # PARENT DOMAIN MANAGEMENT (CRUD)
    # ===============================================================================
    # Simple POST route to fix the 405 error
    @app.route("/api/domains", methods=["POST"])
    def create_parent_domain_simple():
        """Create a new parent domain - simplified version"""
        try:
            data = request.json or {}

            if not data.get("domain_name"):
                return (
                    jsonify({"success": False, "error": "domain_name is required"}),
                    400,
                )

            domain_name = data["domain_name"]

            # Basic validation
            if not domain_name or len(domain_name) > 253:
                return jsonify({"success": False, "error": "Invalid domain name"}), 400

            # Try to add to domain manager
            success, message = domain_manager.add_parent_domain(
                domain_name,
                port_range_start=data.get("port_range_start"),
                port_range_end=data.get("port_range_end"),
                description=data.get("description", f"{domain_name} domain"),
                ssl_enabled=data.get("ssl_enabled", True),
            )

            if success:
                return jsonify(
                    {
                        "success": True,
                        "message": message,
                        "domain": {
                            "domain_name": domain_name,
                            "ssl_enabled": data.get("ssl_enabled", True),
                            "status": "active",
                        },
                    }
                )
            else:
                return jsonify({"success": False, "error": message}), 400

        except Exception as e:
            deps["logger"].error(f"Failed to create parent domain: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/domains", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_available_domains():
        """Get list of all parent domains"""
        try:
            domains = domain_manager.get_all_parent_domains()
            return APIResponse.success(
                {
                    "domains": domains,
                    "total_domains": len(domains),
                }
            )

        except Exception as e:
            deps["logger"].error(f"Error getting domains: {e}")
            return APIResponse.success(
                {"domains": [], "total_domains": 0, "error": str(e)}
            )

    @app.route("/api/domains", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def create_parent_domain():
        """Create a new parent domain"""
        try:
            data = request.json
            if not data:
                return APIResponse.bad_request("Request body required")

            domain_name = data.get("domain_name", "").strip()
            if not domain_name:
                return APIResponse.bad_request("domain_name is required")

            port_range_start = data.get("port_range_start")
            port_range_end = data.get("port_range_end")
            description = data.get("description", f"{domain_name} domain")
            ssl_enabled = data.get("ssl_enabled", True)

            # Validate port range
            if port_range_start and port_range_end:
                if not (
                    1 <= port_range_start <= 65535 and 1 <= port_range_end <= 65535
                ):
                    return APIResponse.bad_request("Invalid port range")
                if port_range_start >= port_range_end:
                    return APIResponse.bad_request(
                        "port_range_start must be less than port_range_end"
                    )

            success, message = domain_manager.add_parent_domain(
                domain_name, port_range_start, port_range_end, description, ssl_enabled
            )

            if success:
                return APIResponse.success(
                    {
                        "message": message,
                        "domain": {
                            "domain_name": domain_name,
                            "port_range": [
                                port_range_start or "auto",
                                port_range_end or "auto",
                            ],
                            "description": description,
                            "ssl_enabled": ssl_enabled,
                        },
                    }
                )
            else:
                return APIResponse.bad_request(message)

        except Exception as e:
            deps["logger"].error(f"Failed to create parent domain: {e}")
            return APIResponse.server_error(f"Failed to create domain: {str(e)}")

    @app.route("/api/domains/<domain_name>", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_parent_domain_details(domain_name):
        """Get detailed information about a parent domain"""
        try:
            domain_info = domain_manager.get_parent_domain_info(domain_name)

            if not domain_info:
                return APIResponse.not_found(f"Domain {domain_name} not found")

            return APIResponse.success({"domain": domain_info})

        except Exception as e:
            deps["logger"].error(f"Failed to get parent domain details: {e}")
            return APIResponse.server_error(f"Failed to get domain details: {str(e)}")

    @app.route("/api/domains/<domain_name>", methods=["PUT"])
    @handle_api_errors(deps["logger"])
    def update_parent_domain(domain_name):
        """Update parent domain properties"""
        try:
            data = request.json
            if not data:
                return APIResponse.bad_request("Request body required")

            success, message = domain_manager.update_parent_domain(domain_name, **data)

            if success:
                return APIResponse.success({"message": message})
            else:
                return APIResponse.bad_request(message)

        except Exception as e:
            deps["logger"].error(f"Failed to update parent domain: {e}")
            return APIResponse.server_error(f"Failed to update domain: {str(e)}")

    @app.route("/api/domains/<domain_name>", methods=["DELETE"])
    @handle_api_errors(deps["logger"])
    def delete_parent_domain(domain_name):
        """Delete parent domain"""
        try:
            force = request.args.get("force", "false").lower() == "true"

            success, message = domain_manager.delete_parent_domain(domain_name, force)

            if success:
                return APIResponse.success({"message": message})
            else:
                return APIResponse.bad_request(message)

        except Exception as e:
            deps["logger"].error(f"Failed to delete parent domain: {e}")
            return APIResponse.server_error(f"Failed to delete domain: {str(e)}")

    # ===============================================================================
    # DOMAIN AVAILABILITY AND VALIDATION
    # ===============================================================================

    @app.route("/api/domains/check-availability", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def check_domain_availability():
        """Enhanced domain availability checker using comprehensive nginx + database checking"""
        try:
            data = request.json
            if not data:
                return APIResponse.bad_request("Request body required")

            # Simple domain checking
            if data.get("domain"):
                domain_name = data["domain"].lower().strip()
            elif data.get("subdomain") and data.get("parent_domain"):
                subdomain = data["subdomain"].lower().strip()
                parent_domain = data["parent_domain"]
                domain_name = f"{subdomain}.{parent_domain}"
            else:
                return APIResponse.bad_request(
                    "Either 'domain' or 'subdomain'+'parent_domain' required"
                )

            # Use comprehensive availability checking (nginx + database)
            availability_results = _check_domain_comprehensive(deps, domain_name)

            is_available = all(
                [
                    availability_results["database"]["available"],
                    availability_results["nginx_available"]["available"],
                    availability_results["nginx_enabled"]["available"],
                ]
            )

            # Build response
            response_data = {
                "domain": domain_name,
                "available": is_available,
                "status": "available" if is_available else "taken",
                "checks": availability_results,
            }

            # Add conflict details
            conflicts = []
            for check_name, check_result in availability_results.items():
                if not check_result["available"]:
                    conflicts.append(
                        {
                            "source": check_name,
                            "details": check_result.get("details", {}),
                            "message": check_result.get(
                                "message", f"Domain found in {check_name}"
                            ),
                        }
                    )

            if conflicts:
                response_data["conflicts"] = conflicts
                response_data["message"] = (
                    f"Domain {domain_name} is already in use (found in: {', '.join([c['source'] for c in conflicts])})"
                )
            else:
                response_data["message"] = (
                    f"Domain {domain_name} is available for deployment"
                )
                response_data["ready_for_deployment"] = True

            deps["logger"].info(
                f"Domain availability check: {domain_name} - {'Available' if is_available else 'Taken'}"
            )

            return APIResponse.success(response_data)

        except Exception as e:
            deps["logger"].error(f"Domain availability check failed: {e}")
            return APIResponse.server_error(f"Availability check failed: {str(e)}")

    @app.route("/api/domains/validate", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def validate_domain_only():
        """Validate domain without deploying - for testing validation system"""
        try:
            data = request.json
            if not data or not data.get("domain"):
                return APIResponse.bad_request("Domain required")

            domain_name = data["domain"]
            validator = PreDeploymentValidator(deps)
            is_valid, validation_results = validator.validate_domain_for_deployment(
                domain_name
            )

            return APIResponse.success(
                {
                    "domain": domain_name,
                    "is_available": is_valid,
                    "validation_results": validation_results,
                }
            )

        except Exception as e:
            deps["logger"].error(f"Domain validation failed: {e}")
            return APIResponse.server_error(f"Validation failed: {str(e)}")

    # ===============================================================================
    # SUBDOMAIN MANAGEMENT (CRUD)
    # ===============================================================================

    @app.route("/api/domains/subdomains", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def list_subdomains():
        """List all subdomains with optional filtering"""
        parent_domain = request.args.get("parent_domain")
        status = request.args.get("status", "active")

        try:
            all_domains = deps["hosting_manager"].list_domains()

            # Filter domains
            filtered_domains = []
            for domain in all_domains:
                domain_name = domain["domain_name"]

                # Apply filters
                if parent_domain and not (
                    domain_name == parent_domain
                    or domain_name.endswith(f".{parent_domain}")
                ):
                    continue

                if status != "all" and domain.get("status") != status:
                    continue

                filtered_domains.append(domain)

            return APIResponse.success(
                {
                    "domains": filtered_domains,
                    "count": len(filtered_domains),
                    "filters": {"parent_domain": parent_domain, "status": status},
                }
            )
        except Exception as e:
            deps["logger"].error(f"Error listing subdomains: {e}")
            return APIResponse.success(
                {
                    "domains": [],
                    "count": 0,
                    "filters": {"parent_domain": parent_domain, "status": status},
                    "error": str(e),
                }
            )

    @app.route("/api/domains/subdomains", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def create_subdomain():
        """Create a new subdomain with comprehensive pre-deployment validation"""
        try:
            data = request.json
            if not data:
                return APIResponse.bad_request("Request body required")

            # Validate required fields
            required_fields = ["subdomain", "parent_domain", "app_name"]
            missing_fields = [field for field in required_fields if not data.get(field)]
            if missing_fields:
                return APIResponse.bad_request(
                    f"Missing required fields: {', '.join(missing_fields)}"
                )

            subdomain = data["subdomain"].lower().strip()
            parent_domain = data["parent_domain"]
            app_name = data["app_name"]
            full_domain = f"{subdomain}.{parent_domain}"

            deps["logger"].info(
                f"Starting subdomain creation: {full_domain} for app: {app_name}"
            )

            # Validate subdomain format
            if not DomainValidator._is_valid_subdomain(subdomain):
                return APIResponse.bad_request(f"Invalid subdomain format: {subdomain}")

            # Check if parent domain exists
            valid_parents = [
                d["domain"] for d in domain_manager.get_all_parent_domains()
            ]
            if parent_domain not in valid_parents:
                return APIResponse.bad_request(
                    f"Invalid parent domain. Must be one of: {', '.join(valid_parents)}"
                )

            # CRITICAL: Pre-deployment validation
            validator = PreDeploymentValidator(deps)
            is_valid, validation_results = validator.validate_domain_for_deployment(
                full_domain
            )

            if not is_valid:
                error_message = validator.format_validation_error_message(
                    validation_results
                )
                deps["logger"].warning(
                    f"Pre-deployment validation failed for {full_domain}"
                )

                return APIResponse.bad_request(
                    {
                        "message": f"Cannot deploy {full_domain} - conflicts detected",
                        "error": error_message,
                        "validation_results": validation_results,
                    }
                )

            deps["logger"].info(f"Pre-deployment validation passed for {full_domain}")

            # Port allocation
            port_range = domain_manager.get_port_range_for_domain(parent_domain)
            if not port_range:
                return APIResponse.server_error(
                    f"No port range configured for {parent_domain}"
                )

            allocated_port = allocate_port_for_deployment(
                preferred_port=None,
                start_range=port_range[0],
                end_range=port_range[1],
            )

            deps["logger"].info(f"Allocated port {allocated_port} for {full_domain}")

            # Create domain entry (this should now succeed since validation passed)
            success = deps["hosting_manager"].deploy_domain(
                domain_name=full_domain,
                port=allocated_port,
                site_type="node",
            )

            if not success:
                deps["logger"].error(
                    f"Domain deployment failed for {full_domain} despite validation passing"
                )
                return APIResponse.server_error(
                    "Domain deployment failed - this shouldn't happen after validation"
                )

            result = {
                "domain": full_domain,
                "subdomain": subdomain,
                "parent_domain": parent_domain,
                "app_name": app_name,
                "port": allocated_port,
                "message": f"Subdomain {full_domain} created successfully",
                "url": f"http://{full_domain}",
                "validation_passed": True,
            }

            deps["logger"].info(f"Successfully created subdomain: {full_domain}")
            return APIResponse.success(result)

        except Exception as e:
            deps["logger"].error(f"Subdomain creation exception: {e}", exc_info=True)
            return APIResponse.server_error(f"Subdomain creation failed: {str(e)}")

    @app.route("/api/domains/subdomains/<subdomain_name>", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_subdomain_details(subdomain_name):
        """Get detailed information about a subdomain"""
        try:
            conn = deps["hosting_manager"].get_database_connection()
            if not conn:
                return APIResponse.server_error("Database connection failed")

            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT domain_name, port, site_type, ssl_enabled, status, created_at, updated_at
                FROM domains 
                WHERE domain_name = ?
            """,
                (subdomain_name,),
            )

            row = cursor.fetchone()
            conn.close()

            if not row:
                return APIResponse.not_found(f"Subdomain {subdomain_name} not found")

            subdomain_info = {
                "domain_name": row[0],
                "port": row[1],
                "site_type": row[2],
                "ssl_enabled": bool(row[3]),
                "status": row[4],
                "created_at": row[5],
                "updated_at": row[6],
                "url": f"http://{row[0]}",
            }

            # Add parent domain info if it's a subdomain
            if "." in subdomain_name:
                parts = subdomain_name.split(".")
                subdomain_info["subdomain"] = parts[0]
                subdomain_info["parent_domain"] = ".".join(parts[1:])

            return APIResponse.success({"subdomain": subdomain_info})

        except Exception as e:
            deps["logger"].error(f"Failed to get subdomain details: {e}")
            return APIResponse.server_error(
                f"Failed to get subdomain details: {str(e)}"
            )

    @app.route("/api/domains/subdomains/<subdomain_name>", methods=["PUT"])
    @handle_api_errors(deps["logger"])
    def update_subdomain(subdomain_name):
        """Update subdomain properties"""
        try:
            data = request.json
            if not data:
                return APIResponse.bad_request("Request body required")

            # Get current subdomain info
            conn = deps["hosting_manager"].get_database_connection()
            if not conn:
                return APIResponse.server_error("Database connection failed")

            cursor = conn.cursor()
            cursor.execute(
                "SELECT domain_name, port, site_type FROM domains WHERE domain_name = ?",
                (subdomain_name,),
            )

            current = cursor.fetchone()
            if not current:
                conn.close()
                return APIResponse.not_found(f"Subdomain {subdomain_name} not found")

            # Update allowed fields
            update_fields = []
            values = []

            if "port" in data:
                new_port = int(data["port"])
                if 1 <= new_port <= 65535:
                    update_fields.append("port = ?")
                    values.append(new_port)
                else:
                    return APIResponse.bad_request("Invalid port number")

            if "site_type" in data:
                if data["site_type"] in ["static", "node", "api", "app"]:
                    update_fields.append("site_type = ?")
                    values.append(data["site_type"])
                else:
                    return APIResponse.bad_request("Invalid site_type")

            if not update_fields:
                return APIResponse.bad_request("No valid fields to update")

            values.append(subdomain_name)

            cursor.execute(
                f"""
                UPDATE domains 
                SET {', '.join(update_fields)}, updated_at = CURRENT_TIMESTAMP
                WHERE domain_name = ?
            """,
                values,
            )

            conn.commit()
            conn.close()

            deps["logger"].info(f"Updated subdomain: {subdomain_name}")
            return APIResponse.success(
                {
                    "message": f"Subdomain {subdomain_name} updated successfully",
                    "subdomain": subdomain_name,
                }
            )

        except Exception as e:
            deps["logger"].error(f"Subdomain update failed: {e}")
            return APIResponse.server_error(f"Failed to update subdomain: {str(e)}")

    @app.route("/api/domains/subdomains/<subdomain_name>", methods=["DELETE"])
    @handle_api_errors(deps["logger"])
    def delete_subdomain(subdomain_name):
        """Delete subdomain with complete cleanup"""
        try:
            deps["logger"].info(
                f"Starting complete subdomain deletion: {subdomain_name}"
            )

            cleanup_results = {
                "domain": subdomain_name,
                "timestamp": datetime.now().isoformat(),
                "components_cleaned": [],
                "errors": [],
                "stopped_processes": [],
                "removed_files": [],
            }

            # 1. PM2 Process Cleanup
            try:
                pm2_cleanup = cleanup_pm2_processes_for_domain(
                    subdomain_name, deps["logger"]
                )
                cleanup_results["stopped_processes"] = pm2_cleanup["stopped_processes"]
                cleanup_results["errors"].extend(pm2_cleanup["errors"])

                if pm2_cleanup["total_stopped"] > 0:
                    cleanup_results["components_cleaned"].append("processes")
            except Exception as e:
                cleanup_results["errors"].append(f"PM2 cleanup error: {str(e)}")

            # 2. Nginx Configuration Cleanup
            try:
                nginx_cleanup = cleanup_nginx_config(subdomain_name, deps["logger"])
                cleanup_results["removed_files"].extend(nginx_cleanup["removed_files"])
                cleanup_results["errors"].extend(nginx_cleanup["errors"])

                if nginx_cleanup["success"]:
                    cleanup_results["components_cleaned"].append("nginx")
            except Exception as e:
                cleanup_results["errors"].append(f"Nginx cleanup error: {str(e)}")

            # 3. Application Files Cleanup
            try:
                files_cleanup = cleanup_application_files(
                    subdomain_name, deps["logger"]
                )
                cleanup_results["removed_files"].extend(files_cleanup["removed_files"])
                cleanup_results["errors"].extend(files_cleanup["errors"])

                if files_cleanup["success"]:
                    cleanup_results["components_cleaned"].append("files")
            except Exception as e:
                cleanup_results["errors"].append(f"File cleanup error: {str(e)}")

            # 4. Database Cleanup
            try:
                success = deps["hosting_manager"].remove_domain(subdomain_name)
                if success:
                    cleanup_results["components_cleaned"].append("database")
                else:
                    cleanup_results["errors"].append("Database cleanup failed")

                # Remove health check monitoring
                if hasattr(deps["health_checker"], "remove_health_check"):
                    deps["health_checker"].remove_health_check(subdomain_name)

            except Exception as e:
                cleanup_results["errors"].append(f"Database cleanup error: {str(e)}")

            # Generate summary
            components_count = len(cleanup_results["components_cleaned"])
            error_count = len(cleanup_results["errors"])

            if components_count > 0:
                message = (
                    f"Subdomain {subdomain_name} completely deleted"
                    if error_count == 0
                    else f"Subdomain {subdomain_name} partially deleted ({components_count} components, {error_count} errors)"
                )

                return APIResponse.success(
                    {
                        "message": message,
                        "summary": {
                            "components_cleaned": components_count,
                            "files_removed": len(cleanup_results["removed_files"]),
                            "processes_stopped": len(
                                cleanup_results["stopped_processes"]
                            ),
                            "errors": error_count,
                        },
                        "details": cleanup_results,
                    }
                )
            else:
                return APIResponse.server_error(
                    f"No components could be cleaned for {subdomain_name}"
                )

        except Exception as e:
            deps["logger"].error(
                f"Subdomain deletion exception for {subdomain_name}: {e}"
            )
            return APIResponse.server_error(f"Deletion failed: {str(e)}")

    # ===============================================================================
    # CLEANUP ROUTES
    # ===============================================================================

    @app.route("/api/domains/cleanup", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_domains_for_cleanup():
        """Get list of all domains that can be cleaned up"""
        try:
            all_domains = deps["hosting_manager"].list_domains()
            cleanup_candidates = []

            for domain in all_domains:
                domain_name = domain.get("domain_name")
                if not domain_name:
                    continue

                # Get process information
                pm2_processes = []
                try:
                    if hasattr(deps["process_monitor"], "get_all_processes"):
                        all_processes = deps["process_monitor"].get_all_processes()
                        pm2_processes = [
                            p
                            for p in all_processes
                            if p.get("name") == domain_name
                            or domain_name in p.get("cwd", "")
                        ]
                except Exception as e:
                    deps["logger"].warning(
                        f"Could not get processes for {domain_name}: {e}"
                    )

                cleanup_info = {
                    "domain_name": domain_name,
                    "status": domain.get("status", "unknown"),
                    "created_at": domain.get("created_at"),
                    "app_name": domain_name.split(".")[0],
                    "port": domain.get("port"),
                    "process_count": len(pm2_processes),
                    "processes": [
                        {
                            "name": p.get("name", "unknown"),
                            "status": p.get("status", "unknown"),
                            "pid": p.get("pid"),
                        }
                        for p in pm2_processes
                    ],
                    "can_cleanup": True,
                    "cleanup_components": ["database", "processes", "nginx", "files"],
                }

                cleanup_candidates.append(cleanup_info)

            return APIResponse.success(
                {
                    "domains": cleanup_candidates,
                    "total_count": len(cleanup_candidates),
                    "active_processes": sum(
                        d["process_count"] for d in cleanup_candidates
                    ),
                    "timestamp": datetime.now().isoformat(),
                }
            )

        except Exception as e:
            deps["logger"].error(f"Cleanup candidates error: {e}")
            return APIResponse.success(
                {
                    "domains": [],
                    "total_count": 0,
                    "active_processes": 0,
                    "timestamp": datetime.now().isoformat(),
                    "error": f"Error getting cleanup info: {str(e)}",
                }
            )

    @app.route("/api/domains/<domain_name>/cleanup", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def cleanup_specific_domain(domain_name):
        """Complete cleanup with comprehensive component removal"""
        try:
            data = request.json or {}
            components = data.get(
                "components", ["processes", "nginx", "files", "database"]
            )

            deps["logger"].info(
                f"Starting comprehensive cleanup for domain: {domain_name}"
            )

            cleanup_results = {
                "domain": domain_name,
                "timestamp": datetime.now().isoformat(),
                "components_cleaned": [],
                "errors": [],
                "stopped_processes": [],
                "removed_files": [],
            }

            # 1. PM2 Process Cleanup
            if "processes" in components:
                try:
                    pm2_cleanup = cleanup_pm2_processes_for_domain(
                        domain_name, deps["logger"]
                    )
                    cleanup_results["stopped_processes"] = pm2_cleanup[
                        "stopped_processes"
                    ]
                    cleanup_results["errors"].extend(pm2_cleanup["errors"])

                    if pm2_cleanup["total_stopped"] > 0:
                        cleanup_results["components_cleaned"].append("processes")
                except Exception as e:
                    cleanup_results["errors"].append(f"PM2 cleanup error: {str(e)}")

            # 2. Nginx Configuration Cleanup
            if "nginx" in components:
                try:
                    nginx_cleanup = cleanup_nginx_config(domain_name, deps["logger"])
                    cleanup_results["removed_files"].extend(
                        nginx_cleanup["removed_files"]
                    )
                    cleanup_results["errors"].extend(nginx_cleanup["errors"])

                    if nginx_cleanup["success"]:
                        cleanup_results["components_cleaned"].append("nginx")
                except Exception as e:
                    cleanup_results["errors"].append(f"Nginx cleanup error: {str(e)}")

            # 3. Application Files Cleanup
            if "files" in components:
                try:
                    files_cleanup = cleanup_application_files(
                        domain_name, deps["logger"]
                    )
                    cleanup_results["removed_files"].extend(
                        files_cleanup["removed_files"]
                    )
                    cleanup_results["errors"].extend(files_cleanup["errors"])

                    if files_cleanup["success"]:
                        cleanup_results["components_cleaned"].append("files")
                except Exception as e:
                    cleanup_results["errors"].append(f"File cleanup error: {str(e)}")

            # 4. Database Cleanup
            if "database" in components:
                try:
                    success = deps["hosting_manager"].remove_domain(domain_name)
                    if success:
                        cleanup_results["components_cleaned"].append("database")
                    else:
                        cleanup_results["errors"].append("Database cleanup failed")

                    # Remove health check monitoring
                    try:
                        if hasattr(deps["health_checker"], "remove_health_check"):
                            deps["health_checker"].remove_health_check(domain_name)
                    except Exception as e:
                        deps["logger"].warning(f"Could not remove health check: {e}")

                except Exception as e:
                    cleanup_results["errors"].append(
                        f"Database cleanup error: {str(e)}"
                    )

            # Generate summary
            components_count = len(cleanup_results["components_cleaned"])
            error_count = len(cleanup_results["errors"])

            if components_count > 0:
                message = (
                    f"Domain {domain_name} completely cleaned up"
                    if error_count == 0
                    else f"Domain {domain_name} partially cleaned up ({components_count} components, {error_count} errors)"
                )

                return APIResponse.success(
                    {
                        "message": message,
                        "summary": {
                            "components_cleaned": components_count,
                            "files_removed": len(cleanup_results["removed_files"]),
                            "processes_stopped": len(
                                cleanup_results["stopped_processes"]
                            ),
                            "errors": error_count,
                        },
                        "details": cleanup_results,
                    }
                )
            else:
                return APIResponse.server_error(
                    f"No components could be cleaned for {domain_name}"
                )

        except Exception as e:
            deps["logger"].error(f"Domain cleanup exception for {domain_name}: {e}")
            return APIResponse.server_error(f"Cleanup failed: {str(e)}")

    # ===============================================================================
    # DEPLOYMENT ROUTES
    # ===============================================================================

    def is_port_available(port):
        """Check if a port is available"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(("localhost", port))
                return result != 0
        except:
            return False

    @app.route("/api/deploy/nodejs-subdomain", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def deploy_nodejs_with_subdomain():
        """Deploy Node.js app with subdomain support and pre-deployment validation"""
        try:
            data = request.json

            if not data.get("name") or not data.get("files"):
                return APIResponse.bad_request("Missing name or files")

            if not data.get("domain_config"):
                return APIResponse.bad_request("Domain configuration required")

            domain_config = data["domain_config"]

            # Support both subdomain and root domain deployments
            if domain_config.get("subdomain") and domain_config.get("parent_domain"):
                subdomain = domain_config["subdomain"].lower().strip()
                parent_domain = domain_config["parent_domain"]
                full_domain = f"{subdomain}.{parent_domain}"
                deployment_type = "subdomain"
            elif domain_config.get("root_domain"):
                full_domain = domain_config["root_domain"]
                deployment_type = "root"
                parent_domain = full_domain
            else:
                return APIResponse.bad_request(
                    "Missing subdomain/parent_domain or root_domain"
                )

            site_name = data["name"]
            project_files = data["files"]
            deploy_config = data.get("deployConfig", {})

            deps["logger"].info(
                f"Starting {deployment_type} deployment for {site_name} on {full_domain}"
            )

            # CRITICAL: Pre-deployment validation using new validator
            validator = PreDeploymentValidator(deps)
            is_valid, validation_results = validator.validate_domain_for_deployment(
                full_domain
            )

            if not is_valid:
                error_message = validator.format_validation_error_message(
                    validation_results
                )
                deps["logger"].warning(
                    f"Pre-deployment validation failed for {full_domain}"
                )

                return APIResponse.bad_request(
                    {
                        "message": f"Cannot deploy {full_domain} - conflicts detected",
                        "error": error_message,
                        "validation_results": validation_results,
                    }
                )

            deps["logger"].info(f"Pre-deployment validation passed for {full_domain}")

            # Enhanced port allocation
            allocated_port = None
            preferred_port = deploy_config.get("port")

            # Try preferred port first
            if preferred_port and is_port_available(preferred_port):
                allocated_port = preferred_port

            # Try parent domain range
            if not allocated_port:
                port_range = domain_manager.get_port_range_for_domain(parent_domain)
                if port_range:
                    start_range, end_range = port_range
                    for port in range(start_range, end_range):
                        if is_port_available(port):
                            allocated_port = port
                            break

            # Try broader range
            if not allocated_port:
                for port in range(3001, 5000):
                    if is_port_available(port):
                        allocated_port = port
                        break

            if not allocated_port:
                return APIResponse.server_error("No available ports found")

            # Update deploy config
            deploy_config.update(
                {
                    "port": allocated_port,
                    "domain": full_domain,
                    "env": {
                        "PORT": str(allocated_port),
                        "DOMAIN": full_domain,
                        **deploy_config.get("env", {}),
                    },
                }
            )

            # Deploy the application
            deployment_result = deps["process_monitor"].deploy_nodejs_app(
                site_name, project_files, deploy_config
            )

            if not deployment_result.get("success"):
                error_msg = deployment_result.get("error", "Unknown deployment error")
                return APIResponse.server_error(f"App deployment failed: {error_msg}")

            # Create domain entry
            success = deps["hosting_manager"].deploy_domain(
                domain_name=full_domain,
                port=allocated_port,
                site_type="node",
            )

            if not success:
                # Cleanup on failure
                try:
                    if hasattr(deps["process_monitor"], "stop_process"):
                        deps["process_monitor"].stop_process(site_name)
                except Exception as cleanup_error:
                    deps["logger"].warning(
                        f"Failed to cleanup deployment: {cleanup_error}"
                    )

                return APIResponse.server_error("Domain creation failed")

            # Setup health monitoring
            try:
                if hasattr(deps["health_checker"], "add_health_check"):
                    deps["health_checker"].add_health_check(
                        site_name, f"http://localhost:{allocated_port}"
                    )
            except Exception as e:
                deps["logger"].warning(f"Could not setup health monitoring: {e}")

            # Build final result
            final_result = {
                **deployment_result,
                "domain": {
                    "full_domain": full_domain,
                    "domain_type": deployment_type,
                    "ssl_enabled": False,
                    "url": f"http://{full_domain}",
                    "port": allocated_port,
                },
                "validation_passed": True,
            }

            if deployment_type == "subdomain":
                final_result["domain"]["subdomain"] = subdomain
                final_result["domain"]["parent_domain"] = parent_domain

            deps["logger"].info(
                f"Domain deployment successful: {full_domain} on port {allocated_port}"
            )
            return APIResponse.success(final_result)

        except Exception as e:
            deps["logger"].error(f"Domain deployment exception: {e}")
            return APIResponse.server_error(f"Domain deployment failed: {str(e)}")

    # ===============================================================================
    # UTILITY ROUTES
    # ===============================================================================

    @app.route("/api/domains/status", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_domain_status():
        """Get overall domain system status"""
        try:
            parent_domains = domain_manager.get_all_parent_domains()
            all_subdomains = deps["hosting_manager"].list_domains()

            return APIResponse.success(
                {
                    "parent_domains": len(parent_domains),
                    "total_subdomains": len(all_subdomains),
                    "active_subdomains": len(
                        [d for d in all_subdomains if d.get("status") == "active"]
                    ),
                    "timestamp": datetime.now().isoformat(),
                }
            )

        except Exception as e:
            deps["logger"].error(f"Failed to get domain status: {e}")
            return APIResponse.server_error("Failed to get domain status")

    # Log successful registration
    deps["logger"].info(
        "Dynamic domain routes registered successfully with full CRUD support"
    )
    return True
