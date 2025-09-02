# src/api/app.py - Main Flask application (hardened + debug helpers)
from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime
import os
import traceback

# Optional imports: never block API boot if they fail
try:
    from .routes import register_all_routes  # your aggregator

    ROUTES_AVAILABLE = True
    ROUTES_IMPORT_ERROR = None
except Exception as e:
    register_all_routes = None  # type: ignore
    ROUTES_AVAILABLE = False
    ROUTES_IMPORT_ERROR = e

try:
    from .middleware import setup_error_handlers, setup_logging_middleware

    MIDDLEWARE_AVAILABLE = True
    MIDDLEWARE_IMPORT_ERROR = None
except Exception as e:
    setup_error_handlers = setup_logging_middleware = None  # type: ignore
    MIDDLEWARE_AVAILABLE = False
    MIDDLEWARE_IMPORT_ERROR = e


class HostingAPI:
    """Streamlined API application (resilient boot + debug endpoints)."""

    def __init__(
        self, hosting_manager, process_monitor, health_checker, config, logger
    ):
        self.app = Flask(__name__)
        CORS(self.app)

        self.dependencies = {
            "hosting_manager": hosting_manager,
            "process_monitor": process_monitor,
            "health_checker": health_checker,
            "config": config,
            "logger": logger,
        }
        self.logger = logger

        # Middleware (non-fatal)
        if MIDDLEWARE_AVAILABLE:
            try:
                setup_error_handlers(self.app)
                setup_logging_middleware(self.app, logger)
            except Exception as e:
                logger.warning(f"Middleware setup failed: {e}")
                logger.debug("Middleware traceback:\n" + traceback.format_exc())
        else:
            logger.warning(f"Middleware not loaded: {MIDDLEWARE_IMPORT_ERROR}")

        # Always-on minimal endpoints
        self._inject_minimal_endpoints()

        # Register your full route set (never block boot)
        self._register_all_routes_safe()

        # Debug helpers (see what actually loaded)
        self._inject_debug_endpoints()

        logger.info("API routes registered:")
        for rule in self.app.url_map.iter_rules():
            logger.info(f"  {sorted(rule.methods)} {rule.rule}")

    # ---- internal ------------------------------------------------------------
    def _register_all_routes_safe(self):
        """Call routes.register_all_routes but capture module-by-module results."""
        if not ROUTES_AVAILABLE or not callable(register_all_routes):
            self.app.config["ROUTE_LOAD_RESULTS"] = {
                "ok": False,
                "error": str(ROUTES_IMPORT_ERROR),
                "modules": [],
            }
            self.logger.warning(f"routes package import failed: {ROUTES_IMPORT_ERROR}")
            return

        try:
            # register_all_routes will now populate app.config["ROUTE_LOAD_RESULTS"]
            register_all_routes(self.app, self.dependencies)
            if "ROUTE_LOAD_RESULTS" not in self.app.config:
                # legacy register_all_routes that didn't set results
                self.app.config["ROUTE_LOAD_RESULTS"] = {"ok": True, "modules": []}
            self.logger.info("routes.register_all_routes() executed")
        except Exception as e:
            self.app.config["ROUTE_LOAD_RESULTS"] = {
                "ok": False,
                "error": f"{e}",
                "modules": [],
                "traceback": traceback.format_exc(),
            }
            self.logger.error(f"Route registration failed: {e}")
            self.logger.debug(self.app.config["ROUTE_LOAD_RESULTS"]["traceback"])

    def _inject_minimal_endpoints(self):
        app = self.app

        @app.route("/api/health", methods=["GET"])
        def health_check():
            try:
                hm = self.dependencies["hosting_manager"]
                pm = self.dependencies["process_monitor"]
                return jsonify(
                    {
                        "status": "healthy",
                        "timestamp": datetime.now().isoformat(),
                        "version": "3.0.0",
                        "service": "Hosting Manager API",
                        "readonly_filesystem": getattr(hm, "readonly_filesystem", None),
                        "pm2_available": getattr(pm, "pm2_available", False),
                    }
                )
            except Exception as e:
                return jsonify({"status": "error", "error": str(e)}), 500

        @app.route("/api/status", methods=["GET"])
        def get_system_status():
            try:
                status = self.dependencies["hosting_manager"].get_system_status()
                return jsonify({"success": True, "status": status})
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 500

        @app.route("/api/processes", methods=["GET"])
        def get_processes():
            try:
                pm = self.dependencies["process_monitor"]
                processes = pm.get_all_processes()
                summary = pm.get_process_summary()
                return jsonify(
                    {
                        "success": True,
                        "timestamp": datetime.now().isoformat(),
                        "summary": summary,
                        "processes": processes,
                    }
                )
            except Exception as e:
                self.logger.error(f"Failed to get processes: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @app.errorhandler(404)
        def not_found(err):
            return jsonify({"success": False, "error": "Endpoint not found"}), 404

    def _inject_debug_endpoints(self):
        app = self.app

        @app.route("/api/_debug/routes", methods=["GET"])
        def list_routes():
            routes = []
            for rule in self.app.url_map.iter_rules():
                routes.append(
                    {
                        "rule": rule.rule,
                        "methods": sorted(
                            m for m in rule.methods if m not in ("HEAD", "OPTIONS")
                        ),
                    }
                )
            return jsonify({"success": True, "count": len(routes), "routes": routes})

        @app.route("/api/_debug/routes/load-status", methods=["GET"])
        def routes_load_status():
            return jsonify(
                {
                    "success": True,
                    "results": self.app.config.get(
                        "ROUTE_LOAD_RESULTS", {"ok": None, "modules": []}
                    ),
                }
            )

        @app.route("/api/_debug/env", methods=["GET"])
        def env():
            keys = ["PYTHONPATH", "FLASK_ENV", "HOSTING_ENV", "PORT", "NODE_ENV"]
            data = {k: os.environ.get(k) for k in keys}
            return jsonify({"success": True, "env": data})

        @app.route("/api/_debug/ping", methods=["GET"])
        def ping():
            return jsonify({"pong": True, "time": datetime.now().isoformat()})

    # ---- run -----------------------------------------------------------------
    def run(self, host="0.0.0.0", port=5000):
        logger = self.dependencies["logger"]
        hm = self.dependencies["hosting_manager"]

        logger.info(f"Starting Hosting Manager API v3.0 on http://{host}:{port}")
        try:
            logger.info(f"Running as: {getattr(hm, 'current_user', 'unknown')}")
        except Exception:
            pass

        # Start background services (non-fatal)
        try:
            self.dependencies["process_monitor"].start_background_monitoring()
        except Exception as e:
            logger.warning(f"process_monitor.start_background_monitoring failed: {e}")
        try:
            self.dependencies["health_checker"].start_background_checks()
        except Exception as e:
            logger.warning(f"health_checker.start_background_checks failed: {e}")

        # Status line
        try:
            status = hm.get_system_status()
            logger.info(
                f"System ready - {status.get('domain_count', 0)} domains, "
                f"{status.get('active_apps', 0)} apps running"
            )
        except Exception:
            pass

        self.app.run(
            host=host, port=port, debug=False, use_reloader=False, threaded=True
        )
