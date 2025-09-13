# src/api/routes/domains.py
"""
API routes for domain and subdomain management
"""

import json
import shutil
import subprocess
import glob
import os
import socket
import re
import functools
from flask import request, jsonify
from datetime import datetime


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


class DomainValidator:
    """Domain validation utilities"""

    @staticmethod
    def validate_domain_deployment(data):
        """Validate domain deployment request"""
        errors = []

        if not data.get("domain_config"):
            errors.append("Domain configuration is required")
            return False, errors

        domain_config = data["domain_config"]
        subdomain = domain_config.get("subdomain", "").strip()
        if not subdomain:
            errors.append("Subdomain is required")
        elif not DomainValidator._is_valid_subdomain(subdomain):
            errors.append("Invalid subdomain format")

        parent_domain = domain_config.get("parent_domain", "").strip()
        valid_domains = ["smartwave.co.za", "datablox.co.za", "mondaycafe.co.za"]
        if not parent_domain:
            errors.append("Parent domain is required")
        elif parent_domain not in valid_domains:
            errors.append(
                f"Invalid parent domain. Must be one of: {', '.join(valid_domains)}"
            )

        return len(errors) == 0, errors

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

    @staticmethod
    def parse_domain_input(data):
        """Parse domain input data - returns (full_domain, domain_type, error_message)"""
        if data.get("subdomain") and data.get("parent_domain"):
            subdomain = data["subdomain"].lower().strip()
            parent_domain = data["parent_domain"]

            if not DomainValidator._is_valid_subdomain(subdomain):
                return None, None, "Invalid subdomain format"

            valid_parent_domains = [
                "smartwave.co.za",
                "datablox.co.za",
                "mondaycafe.co.za",
            ]
            if parent_domain not in valid_parent_domains:
                return (
                    None,
                    None,
                    f"Invalid parent domain. Must be one of: {', '.join(valid_parent_domains)}",
                )

            full_domain = f"{subdomain}.{parent_domain}"
            return full_domain, "subdomain", None

        elif data.get("domain"):
            domain = data["domain"].lower().strip()
            valid_root_domains = [
                "smartwave.co.za",
                "datablox.co.za",
                "mondaycafe.co.za",
            ]

            if domain in valid_root_domains:
                return domain, "root_domain", None
            else:
                # Check if valid subdomain
                for root_domain in valid_root_domains:
                    if domain.endswith(f".{root_domain}"):
                        subdomain_part = domain.replace(f".{root_domain}", "")
                        if DomainValidator._is_valid_subdomain(subdomain_part):
                            return domain, "subdomain", None

                return None, None, "Invalid domain format or unsupported parent domain"

        return None, None, "Either 'subdomain'+'parent_domain' or 'domain' required"

    @staticmethod
    def get_port_range_for_domain(parent_domain):
        """Get port range for parent domain"""
        port_ranges = {
            "datablox.co.za": [3101, 3200],
            "smartwave.co.za": [3001, 3100],
            "mondaycafe.co.za": [3201, 3300],
        }
        return port_ranges.get(parent_domain)


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
    """Register domain management routes"""

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

    # ===============================================================================
    # MAIN DOMAIN ROUTES
    # ===============================================================================

    @app.route("/api/domains", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_available_domains():
        """Get list of available parent domains"""
        try:
            available_domains = {
                "smartwave.co.za": {
                    "port_range": [3001, 3100],
                    "ssl_enabled": True,
                    "description": "SmartWave Technology Domain",
                },
                "datablox.co.za": {
                    "port_range": [3101, 3200],
                    "ssl_enabled": True,
                    "description": "DataBlox Analytics Domain",
                },
                "mondaycafe.co.za": {
                    "port_range": [3201, 3300],
                    "ssl_enabled": True,
                    "description": "Monday Cafe Domain",
                },
            }

            # Get current usage stats
            try:
                all_domains = deps["hosting_manager"].list_domains()
            except Exception as e:
                deps["logger"].warning(f"Could not get domain usage stats: {e}")
                all_domains = []

            # Convert to array format
            domains_array = []
            for domain_name, config in available_domains.items():
                allocated_domains = [
                    d
                    for d in all_domains
                    if d.get("domain_name") == domain_name
                    or d.get("domain_name", "").endswith(f".{domain_name}")
                ]

                domain_info = {
                    "id": domain_name,
                    "name": domain_name,
                    "domain": domain_name,
                    "current_subdomains": len(allocated_domains),
                    "available_ports": config["port_range"][1]
                    - config["port_range"][0]
                    - len(allocated_domains),
                    "example_subdomain": f"myapp.{domain_name}",
                    "port_range": config["port_range"],
                    "ssl_enabled": config["ssl_enabled"],
                    "description": config["description"],
                }

                domains_array.append(domain_info)

            return APIResponse.success(
                {
                    "domains": domains_array,
                    "total_domains": len(domains_array),
                }
            )

        except Exception as e:
            deps["logger"].error(f"Error getting domains: {e}")
            return APIResponse.success(
                {"domains": [], "total_domains": 0, "error": str(e)}
            )

    @app.route("/api/domains/check-availability", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def check_domain_availability():
        """Enhanced domain availability checker using comprehensive nginx + database checking"""
        try:
            data = request.json
            if not data:
                return APIResponse.bad_request("Request body required")

            # Parse and validate domain input
            full_domain, domain_type, error_message = (
                DomainValidator.parse_domain_input(data)
            )
            if error_message:
                return APIResponse.bad_request(error_message)

            # Use comprehensive availability checking (nginx + database)
            availability_results = _check_domain_comprehensive(deps, full_domain)

            is_available = all(
                [
                    availability_results["database"]["available"],
                    availability_results["nginx_available"]["available"],
                    availability_results["nginx_enabled"]["available"],
                ]
            )

            # Build response
            response_data = {
                "domain": full_domain,
                "available": is_available,
                "domain_type": domain_type,
                "status": "available" if is_available else "taken",
                "checks": availability_results,
            }

            # Add domain-specific information
            if domain_type == "subdomain":
                parts = full_domain.split(".")
                response_data["subdomain"] = parts[0]
                response_data["parent_domain"] = ".".join(parts[1:])
                response_data["port_range"] = DomainValidator.get_port_range_for_domain(
                    response_data["parent_domain"]
                )

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
                    f"Domain {full_domain} is already in use (found in: {', '.join([c['source'] for c in conflicts])})"
                )
            else:
                response_data["message"] = (
                    f"Domain {full_domain} is available for deployment"
                )
                response_data["ready_for_deployment"] = True

                # Add deployment guidance
                if domain_type == "subdomain":
                    response_data["deployment_endpoint"] = (
                        "/api/deploy/nodejs-subdomain"
                    )
                else:
                    response_data["deployment_endpoint"] = (
                        "/api/deploy/nodejs-root-domain"
                    )

            deps["logger"].info(
                f"Domain availability check: {full_domain} - {'Available' if is_available else 'Taken'}"
            )

            return APIResponse.success(response_data)

        except Exception as e:
            deps["logger"].error(f"Domain availability check failed: {e}")
            return APIResponse.server_error(f"Availability check failed: {str(e)}")

    @app.route("/api/domains/subdomains", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def create_subdomain():
        """Create a new subdomain"""
        data = request.json

        required_fields = ["subdomain", "parent_domain", "app_name"]
        for field in required_fields:
            if not data.get(field):
                return APIResponse.bad_request(f"Missing required field: {field}")

        subdomain = data["subdomain"].lower().strip()
        parent_domain = data["parent_domain"]
        app_name = data["app_name"]
        full_domain = f"{subdomain}.{parent_domain}"

        try:
            success = deps["hosting_manager"].deploy_domain(
                domain_name=full_domain,
                port=3000,  # Default port, updated during deployment
                site_type="node",
            )

            if success:
                result = {
                    "success": True,
                    "domain": full_domain,
                    "app_name": app_name,
                    "message": f"Subdomain {full_domain} created successfully",
                }
                deps["logger"].info(
                    f"Created subdomain: {full_domain} for app: {app_name}"
                )
                return APIResponse.success(result)
            else:
                return APIResponse.server_error("Failed to create subdomain")
        except Exception as e:
            deps["logger"].error(f"Error creating subdomain: {e}")
            return APIResponse.server_error(f"Failed to create subdomain: {str(e)}")

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
        """Deploy Node.js app with subdomain support"""
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

            # Check domain availability using comprehensive checker
            availability_results = _check_domain_comprehensive(deps, full_domain)
            is_available = all(
                [
                    availability_results["database"]["available"],
                    availability_results["nginx_available"]["available"],
                    availability_results["nginx_enabled"]["available"],
                ]
            )

            if not is_available:
                return APIResponse.bad_request(
                    f"Domain {full_domain} is already in use"
                )

            # Enhanced port allocation
            allocated_port = None
            preferred_port = deploy_config.get("port")

            # Try preferred port first
            if preferred_port and is_port_available(preferred_port):
                allocated_port = preferred_port

            # Try parent domain range
            if not allocated_port:
                port_range = DomainValidator.get_port_range_for_domain(parent_domain)
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
            try:
                all_domains = deps["hosting_manager"].list_domains()
                total_domains = len(all_domains)
            except Exception as e:
                deps["logger"].warning(f"Could not get domain count: {e}")
                total_domains = 0

            return APIResponse.success(
                {
                    "total_subdomains": total_domains,
                    "parent_domains": 3,  # smartwave, datablox, mondaycafe
                    "timestamp": datetime.now().isoformat(),
                }
            )

        except Exception as e:
            deps["logger"].error(f"Failed to get domain status: {e}")
            return APIResponse.server_error("Failed to get domain status")

    # Log successful registration
    deps["logger"].info("Domain routes registered successfully")
    return True
