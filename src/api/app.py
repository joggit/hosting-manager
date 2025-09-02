# src/api/app.py - Main Flask application
from flask import Flask
from flask_cors import CORS
from datetime import datetime
from api.server import HostingAPI
from .routes import register_all_routes
from .middleware import setup_error_handlers, setup_logging_middleware
from .utils import APIResponse


class HostingAPI:
    """Streamlined API application"""

    def __init__(
        self, hosting_manager, process_monitor, health_checker, config, logger
    ):
        self.app = Flask(__name__)
        CORS(self.app)

        # Store dependencies for injection
        self.dependencies = {
            "hosting_manager": hosting_manager,
            "process_monitor": process_monitor,
            "health_checker": health_checker,
            "config": config,
            "logger": logger,
        }

        # Setup middleware
        setup_error_handlers(self.app)
        setup_logging_middleware(self.app, logger)

        # Register all routes with dependency injection
        register_all_routes(self.app, self.dependencies)

        logger.info("API routes registered:")
        for rule in self.app.url_map.iter_rules():
            logger.info(f"  {list(rule.methods)} {rule.rule}")

    def run(self, host="0.0.0.0", port=5000):
        """Start the API server"""
        logger = self.dependencies["logger"]
        logger.info(f"Starting Hosting Manager API v3.0 on http://{host}:{port}")
        logger.info(f"Running as: {self.dependencies['hosting_manager'].current_user}")

        # Start background services
        self._start_background_services()

        # Show status
        status = self.dependencies["hosting_manager"].get_system_status()
        logger.info(
            f"System ready - {status['domain_count']} domains, {status['active_apps']} apps running"
        )

        self.app.run(
            host=host, port=port, debug=False, use_reloader=False, threaded=True
        )

    def _start_background_services(self):
        """Start monitoring services"""
        try:
            self.dependencies["process_monitor"].start_background_monitoring()
            self.dependencies["health_checker"].start_background_checks()
        except Exception as e:
            self.dependencies["logger"].warning(
                f"Failed to start background monitoring: {e}"
            )
