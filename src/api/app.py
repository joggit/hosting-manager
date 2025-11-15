# src/api/app.py - Fixed version
"""
Hosting API v3.0 - Clean version with proper route registration
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import os
import subprocess
import json
import time
import shutil

# Import your existing port checker
from utils.port_checker import PortChecker, allocate_port_for_deployment


class HostingAPI:
    """Clean Hosting API with proper route registration"""

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
        allowed = os.getenv(
            "ALLOWED_ORIGINS", "http://localhost:3001,https://your-frontend.example"
        ).split(",")
        CORS(
            self.app,
            origins=[o.strip() for o in allowed],
            methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Content-Type", "Authorization"],
            supports_credentials=True,
        )

        # Store dependencies
        self.deps = {
            "hosting_manager": hosting_manager,
            "process_monitor": process_monitor,
            "health_checker": health_checker,
            "config": config,
            "logger": logger,
        }

        if domain_manager:
            self.deps["domain_manager"] = domain_manager

        # Initialize port checker
        self.port_checker = PortChecker()

        # Register core routes first
        self._register_core_routes()

        # Then register all modular routes
        self.register_all_routes()

    def register_all_routes(self):
        """Register all modular routes using the proper registration system"""
        try:
            # Import and use the proper route registration system
            from api.routes import register_all_routes

            register_all_routes(self.app, self.deps)

            if self.deps.get("logger"):
                self.deps["logger"].info("All modular routes registered successfully")

        except ImportError as e:
            if self.deps.get("logger"):
                self.deps["logger"].error(
                    f"Could not import route registration system: {e}"
                )
        except Exception as e:
            if self.deps.get("logger"):
                self.deps["logger"].error(f"Route registration failed: {e}")

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

        @self.app.route("/api/health", methods=["GET"])
        def health_check():
            """Health check endpoint"""
            return {
                "success": True,
                "data": {"status": "healthy", "timestamp": datetime.now().isoformat()},
            }

        @self.app.route("/api/status", methods=["GET"])
        def api_status():
            """Get system status"""
            try:
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

        @self.app.route("/api/check-ports", methods=["POST"])
        def check_ports():
            """Check port availability"""
            try:
                data = request.get_json()
                start_port = data.get("startPort", 3001)
                count = data.get("count", 100)
                exclude_ports = set(data.get("excludePorts", []))

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
                    jsonify({"success": False, "error": str(e), "availablePorts": []}),
                    500,
                )

        # Route registration status endpoint for debugging
        @self.app.route("/api/debug/routes", methods=["GET"])
        def debug_routes():
            """Debug endpoint to see route registration status"""
            try:
                routes = []
                for rule in self.app.url_map.iter_rules():
                    routes.append(
                        {
                            "endpoint": rule.endpoint,
                            "methods": list(rule.methods),
                            "rule": rule.rule,
                        }
                    )

                # Get route load results if available
                route_results = self.app.config.get("ROUTE_LOAD_RESULTS", {})

                return jsonify(
                    {
                        "success": True,
                        "routes": routes,
                        "route_count": len(routes),
                        "route_load_results": route_results,
                        "timestamp": datetime.now().isoformat(),
                    }
                )
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 500

        # Helper methods
        def _verify_app_running(self, app_name, port):
            """Verify that the app is running"""
            try:
                import requests

                response = requests.get(f"http://localhost:{port}", timeout=5)
                return True
            except:
                # Check PM2 status as fallback
                try:
                    result = subprocess.run(
                        ["pm2", "describe", app_name], capture_output=True, text=True
                    )
                    if result.returncode == 0:
                        data = json.loads(result.stdout)
                        if data and len(data) > 0:
                            status = data[0].get("pm2_env", {}).get("status")
                            return status == "online"
                except:
                    pass
                return False

        def _cleanup_failed_deployment(self, app_name):
            """Cleanup failed deployment"""
            try:
                subprocess.run(["pm2", "delete", app_name], capture_output=True)
                app_dir = f"{self.deps['config'].get('web_root')}/{app_name}"
                if os.path.exists(app_dir):
                    shutil.rmtree(app_dir)
                if self.deps.get("logger"):
                    self.deps["logger"].info(
                        f"Cleaned up failed deployment for {app_name}"
                    )
            except Exception as e:
                if self.deps.get("logger"):
                    self.deps["logger"].warning(f"Cleanup failed for {app_name}: {e}")

        # Store helper methods on the instance for access in routes
        self._verify_app_running = _verify_app_running
        self._cleanup_failed_deployment = _cleanup_failed_deployment

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
