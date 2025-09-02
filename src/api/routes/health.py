# src/api/routes/health.py - Health check routes
from flask import jsonify
from datetime import datetime
from ..utils import APIResponse, handle_api_errors


def register_health_routes(app, deps):
    """Register health check routes"""

    @app.route("/api/health", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def health_check():
        return APIResponse.success(
            {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "version": "3.0.0",
                "service": "Hosting Manager API with Enhanced Monitoring",
                "readonly_filesystem": deps["hosting_manager"].readonly_filesystem,
                "pm2_available": deps["process_monitor"].pm2_available,
                "monitoring_active": deps["process_monitor"].is_monitoring_active(),
            }
        )

    @app.route("/api/status", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_system_status():
        status = deps["hosting_manager"].get_system_status()

        # Add monitoring data
        status.update(
            {
                "monitoring": {
                    "process_monitor_active": deps[
                        "process_monitor"
                    ].is_monitoring_active(),
                    "health_checker_active": deps["health_checker"].is_active(),
                    "pm2_available": deps["process_monitor"].pm2_available,
                    "last_health_check": deps["health_checker"].get_last_check_time(),
                },
                "performance": (
                    deps["process_monitor"].get_system_performance()
                    if hasattr(deps["process_monitor"], "get_system_performance")
                    else {}
                ),
            }
        )

        return APIResponse.success({"status": status})
