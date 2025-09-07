# src/api/app.py
"""
Modular Hosting API v3.0 - Compatible with existing structure
Updated to use system-based port checking
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import os
import importlib

# Import your existing port checker
from utils.port_checker import PortChecker, allocate_port_for_deployment


class HostingAPI:
    """Hosting API that works with existing route structure"""

    def __init__(
        self,
        hosting_manager,
        process_monitor,
        health_checker,
        domain_manager=None,
        config=None,
        logger=None,
    ):
        self.app = Flask(__name__)
        CORS(self.app, origins=["*"])

        # Store dependencies
        self.deps = {
            "hosting_manager": hosting_manager,
            "process_monitor": process_monitor,
            "health_checker": health_checker,
            "config": config,
            "logger": logger,
        }

        # Add domain_manager if provided
        if domain_manager:
            self.deps["domain_manager"] = domain_manager

        # Initialize port checker
        self.port_checker = PortChecker()

        # Setup routes
        self._register_core_routes()
        self._register_modular_routes()

    def _register_core_routes(self):
        """Register core API routes"""

        @self.app.route("/", methods=["GET"])
        def root():
            return {
                "success": True,
                "data": {
                    "name": "Hosting Manager API v3.0",
                    "description": "Multi-Domain Hosting Platform",
                    "version": "3.0.0",
                    "timestamp": datetime.now().isoformat(),
                },
            }

        @self.app.route("/api/status", methods=["GET"])
        def api_status():
            """Get overall API and system status"""
            try:
                # Get system status
                system_status = self.deps["hosting_manager"].get_system_status()

                return {
                    "success": True,
                    "data": {
                        "api": {
                            "version": "3.0.0",
                            "timestamp": datetime.now().isoformat(),
                        },
                        "system": system_status,
                    },
                }

            except Exception as e:
                if self.deps.get("logger"):
                    self.deps["logger"].error(f"Status endpoint error: {e}")
                return {"success": False, "error": "Failed to get system status"}, 500

        @self.app.route("/api/health", methods=["GET"])
        def health_check():
            """Simple health check endpoint"""
            return {
                "success": True,
                "data": {"status": "healthy", "timestamp": datetime.now().isoformat()},
            }

    def _register_modular_routes(self):
        """Register all modular route groups"""
        self.register_all_routes()

    def register_all_routes(self):
        """Register all route modules - expected by deployment script"""
        try:
            # Register existing routes dynamically
            self._register_existing_routes()

            # Register domain routes if domain_manager is available
            if "domain_manager" in self.deps:
                self._register_domain_routes()

            if self.deps.get("logger"):
                self.deps["logger"].info("All route modules registered successfully")

        except Exception as e:
            if self.deps.get("logger"):
                self.deps["logger"].error(f"Failed to register routes: {e}")
            else:
                print(f"Failed to register routes: {e}")

    def _register_existing_routes(self):
        """Register existing route modules dynamically"""
        try:
            routes_path = os.path.join(os.path.dirname(__file__), "routes")

            if not os.path.exists(routes_path):
                if self.deps.get("logger"):
                    self.deps["logger"].warning("No existing routes directory found")
                return

            # Get all Python files in routes directory
            route_files = [
                f
                for f in os.listdir(routes_path)
                if f.endswith(".py") and f != "__init__.py"
            ]

            for route_file in route_files:
                try:
                    module_name = route_file[:-3]  # Remove .py extension
                    module_path = f"api.routes.{module_name}"

                    # Import the module
                    route_module = importlib.import_module(module_path)

                    # Look for common registration function names
                    registration_functions = [
                        f"register_{module_name}_routes",
                        "register_routes",
                        "register_all_routes",
                    ]

                    for func_name in registration_functions:
                        if hasattr(route_module, func_name):
                            register_func = getattr(route_module, func_name)
                            register_func(self.app, self.deps)
                            if self.deps.get("logger"):
                                self.deps["logger"].info(
                                    f"Registered routes from {module_name}"
                                )
                            break
                    else:
                        if self.deps.get("logger"):
                            self.deps["logger"].warning(
                                f"No registration function found in {module_name}"
                            )

                except Exception as e:
                    if self.deps.get("logger"):
                        self.deps["logger"].warning(
                            f"Failed to register routes from {route_file}: {e}"
                        )

        except Exception as e:
            if self.deps.get("logger"):
                self.deps["logger"].error(f"Error scanning routes directory: {e}")

    def _register_domain_routes(self):
        """Register domain management routes with existing port checker"""
        try:

            @self.app.route("/api/domains", methods=["GET"])
            def get_available_domains():
                """Get list of available parent domains"""
                try:
                    domain_manager = self.deps["domain_manager"]
                    domains = domain_manager.get_available_domains()

                    # Format domains for frontend consumption
                    domain_list = []
                    for domain_name, config in domains.items():
                        domain_list.append(
                            {
                                "id": len(domain_list) + 1,
                                "domain": domain_name,
                                "name": config.get("name", domain_name),
                                "port_range": config.get("port_range", [3001, 4000]),
                                "ssl_enabled": config.get("ssl_enabled", True),
                                "status": "active",
                            }
                        )

                    return {
                        "success": True,
                        "domains": domain_list,
                        "server_url": self.deps.get("config", {}).get(
                            "server_url", "http://localhost:5000"
                        ),
                    }
                except Exception as e:
                    if self.deps.get("logger"):
                        self.deps["logger"].error(f"Domain listing error: {e}")
                    return {"success": False, "error": "Failed to get domains"}, 500

            @self.app.route(
                "/api/domains/<parent_domain>/subdomains/check", methods=["POST"]
            )
            def check_subdomain_availability(parent_domain):
                """Check if a subdomain is available"""
                try:
                    data = request.json
                    subdomain = data.get("subdomain", "").lower().strip()

                    if not subdomain:
                        return {"success": False, "error": "Subdomain is required"}, 400

                    domain_manager = self.deps["domain_manager"]
                    available, message = domain_manager.check_subdomain_availability(
                        subdomain, parent_domain
                    )

                    return {
                        "success": True,
                        "data": {
                            "available": available,
                            "message": message,
                            "subdomain": subdomain,
                            "full_domain": (
                                f"{subdomain}.{parent_domain}" if available else None
                            ),
                        },
                    }
                except Exception as e:
                    if self.deps.get("logger"):
                        self.deps["logger"].error(f"Subdomain check error: {e}")
                    return {"success": False, "error": "Failed to check subdomain"}, 500

            @self.app.route("/api/check-ports", methods=["POST"])
            def check_ports():
                """API endpoint to check port availability using existing port checker"""
                try:
                    data = request.get_json()
                    start_port = data.get("startPort", 3001)
                    count = data.get("count", 100)
                    exclude_ports = set(data.get("excludePorts", []))

                    # Use existing port checker
                    available_ports = self.port_checker.get_available_ports(
                        start_port=start_port, count=count, exclude_ports=exclude_ports
                    )

                    return jsonify(
                        {
                            "success": True,
                            "availablePorts": available_ports,
                            "totalChecked": count,
                            "totalAvailable": len(available_ports),
                            "method": self.port_checker.preferred_method,
                        }
                    )

                except Exception as e:
                    if self.deps.get("logger"):
                        self.deps["logger"].error(f"Port check API error: {e}")
                    return (
                        jsonify(
                            {"success": False, "error": str(e), "availablePorts": []}
                        ),
                        500,
                    )

            @self.app.route("/api/check-port/<int:port>", methods=["GET"])
            def check_single_port(port):
                """Check if a specific port is available using existing port checker"""
                try:
                    port_info = self.port_checker.get_port_info(port)

                    return jsonify(
                        {
                            "success": True,
                            "port": port,
                            "available": not port_info["in_use"],
                            "details": port_info,
                        }
                    )

                except Exception as e:
                    if self.deps.get("logger"):
                        self.deps["logger"].error(f"Single port check error: {e}")
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": str(e),
                                "port": port,
                                "available": False,
                            }
                        ),
                        500,
                    )

            @self.app.route("/api/deploy/nodejs-domain", methods=["POST"])
            def deploy_nodejs_with_domain():
                """Deploy Node.js app with automatic domain setup using existing port checker"""
                try:
                    data = request.json

                    # Basic validation
                    if not data.get("name") or not data.get("files"):
                        return {"success": False, "error": "Missing name or files"}, 400

                    if not data.get("domain_config"):
                        return {
                            "success": False,
                            "error": "Domain configuration required",
                        }, 400

                    domain_config = data["domain_config"]
                    if not domain_config.get("subdomain") or not domain_config.get(
                        "parent_domain"
                    ):
                        return {
                            "success": False,
                            "error": "Missing subdomain or parent_domain",
                        }, 400

                    site_name = data["name"]
                    project_files = data["files"]
                    deploy_config = data.get("deployConfig", {})

                    subdomain = domain_config["subdomain"].lower().strip()
                    parent_domain = domain_config["parent_domain"]

                    if self.deps.get("logger"):
                        self.deps["logger"].info(
                            f"Starting domain deployment for {site_name} on {subdomain}.{parent_domain}"
                        )

                    domain_manager = self.deps["domain_manager"]

                    # Check subdomain availability
                    available, message = domain_manager.check_subdomain_availability(
                        subdomain, parent_domain
                    )
                    if not available:
                        return {
                            "success": False,
                            "error": f"Subdomain not available: {message}",
                        }, 400

                    # UPDATED: Use existing port allocation function
                    try:
                        # Get preferred port from request
                        preferred_port = deploy_config.get("port")

                        # Get domain-specific port range if available
                        domains = domain_manager.get_available_domains()
                        domain_info = domains.get(parent_domain, {})
                        if domain_info.get("port_range"):
                            start_range, end_range = domain_info["port_range"]
                        else:
                            # Default port range
                            start_range, end_range = 3001, 4000

                        # Use existing allocate_port_for_deployment function
                        allocated_port = allocate_port_for_deployment(
                            preferred_port=preferred_port,
                            start_range=start_range,
                            end_range=end_range,
                        )

                        if self.deps.get("logger"):
                            self.deps["logger"].info(
                                f"Allocated port {allocated_port} for {site_name}"
                            )

                    except Exception as e:
                        if self.deps.get("logger"):
                            self.deps["logger"].error(f"Port allocation failed: {e}")
                        return {
                            "success": False,
                            "error": f"Port allocation failed: {str(e)}",
                        }, 500

                    # Update deploy config with allocated port
                    deploy_config["port"] = allocated_port
                    deploy_config["domain"] = f"{subdomain}.{parent_domain}"

                    # Ensure environment variables include the port
                    if "env" not in deploy_config:
                        deploy_config["env"] = {}
                    deploy_config["env"]["PORT"] = str(allocated_port)
                    deploy_config["env"]["DOMAIN"] = f"{subdomain}.{parent_domain}"

                    if self.deps.get("logger"):
                        self.deps["logger"].info(
                            f"Starting app deployment on port {allocated_port}"
                        )

                    # Deploy the application using process monitor
                    deployment_result = self.deps["process_monitor"].deploy_nodejs_app(
                        site_name, project_files, deploy_config
                    )

                    if deployment_result["success"]:
                        if self.deps.get("logger"):
                            self.deps["logger"].info(
                                f"App deployment successful, creating domain configuration"
                            )

                        # Create the subdomain configuration
                        domain_result = domain_manager.create_subdomain(
                            subdomain, parent_domain, site_name, allocated_port
                        )

                        if domain_result["success"]:
                            # Setup health monitoring
                            if hasattr(self.deps["health_checker"], "add_health_check"):
                                self.deps["health_checker"].add_health_check(
                                    site_name, f"http://localhost:{allocated_port}"
                                )

                            # Determine SSL status and URL scheme
                            ssl_enabled = domain_result.get("ssl_enabled", False)
                            url_scheme = "https" if ssl_enabled else "http"
                            full_domain = f"{subdomain}.{parent_domain}"

                            # Combine results
                            final_result = {
                                **deployment_result,
                                "domain": {
                                    "subdomain": subdomain,
                                    "parent_domain": parent_domain,
                                    "full_domain": full_domain,
                                    "ssl_enabled": ssl_enabled,
                                    "url": f"{url_scheme}://{full_domain}",
                                    "port": allocated_port,
                                },
                            }

                            if self.deps.get("logger"):
                                self.deps["logger"].info(
                                    f"Domain deployment successful: {full_domain} on port {allocated_port}"
                                )

                            return {"success": True, "data": final_result}

                        else:
                            # Domain creation failed - cleanup the deployed app
                            error_msg = domain_result.get(
                                "error", "Unknown domain setup error"
                            )
                            if self.deps.get("logger"):
                                self.deps["logger"].error(
                                    f"App deployed on port {allocated_port} but domain creation failed: {error_msg}"
                                )

                            # Cleanup the deployed app since domain setup failed
                            try:
                                self.deps["process_monitor"].stop_app(site_name)
                                if self.deps.get("logger"):
                                    self.deps["logger"].info(
                                        f"Cleaned up failed deployment for {site_name}"
                                    )
                            except Exception as cleanup_error:
                                if self.deps.get("logger"):
                                    self.deps["logger"].warning(
                                        f"Failed to cleanup deployment: {cleanup_error}"
                                    )

                            return {
                                "success": False,
                                "error": f"App deployed but domain setup failed: {error_msg}",
                            }, 500

                    else:
                        # App deployment failed
                        error_msg = deployment_result.get(
                            "error", "Unknown deployment error"
                        )
                        if self.deps.get("logger"):
                            self.deps["logger"].error(
                                f"App deployment failed for {site_name}: {error_msg}"
                            )
                        return {
                            "success": False,
                            "error": error_msg,
                        }, 500

                except Exception as e:
                    if self.deps.get("logger"):
                        self.deps["logger"].error(f"Domain deployment error: {e}")
                    return {
                        "success": False,
                        "error": f"Domain deployment failed: {str(e)}",
                    }, 500

            if self.deps.get("logger"):
                self.deps["logger"].info(
                    "Domain management routes registered successfully with existing port checker"
                )

        except Exception as e:
            if self.deps.get("logger"):
                self.deps["logger"].error(f"Failed to register domain routes: {e}")

    def run(self, host="0.0.0.0", port=5000, debug=False):
        """Run the Flask application"""
        try:
            if self.deps.get("logger"):
                self.deps["logger"].info(f"Starting Hosting API v3.0 on {host}:{port}")

            self.app.run(host=host, port=port, debug=debug)

        except Exception as e:
            if self.deps.get("logger"):
                self.deps["logger"].error(f"Failed to start API server: {e}")
            raise
