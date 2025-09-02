# src/api/routes/health.py - Basic health routes
from flask import jsonify
from datetime import datetime


def register_health_routes(app, deps):
    """Register health check routes"""

    @app.route("/api/health", methods=["GET"])
    def api_health():
        """Basic health check"""
        return jsonify(
            {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "version": "3.0.0",
                "service": "Hosting Manager API",
            }
        )

    @app.route("/api/status", methods=["GET"])
    def api_status():
        """System status"""
        try:
            hosting_manager = deps.get("hosting_manager")
            if hosting_manager:
                status = hosting_manager.get_system_status()
                return jsonify({"success": True, "status": status})
            else:
                return jsonify(
                    {"success": False, "error": "Hosting manager not available"}
                )
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
