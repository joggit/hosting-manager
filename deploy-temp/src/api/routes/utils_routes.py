# src/api/routes/utils_routes.py - Utility routes
from flask import request
from ..utils import APIResponse, handle_api_errors, PortChecker


def register_routes(app, deps):
    """Register utility routes"""

    @app.route("/api/check-ports", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def check_available_ports():
        data = request.get_json() or {}
        start_port = data.get("startPort", 3001)
        count = data.get("count", 5)

        available_ports = PortChecker.find_available_ports(start_port, count)

        return APIResponse.success({"availablePorts": available_ports})
