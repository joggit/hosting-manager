# src/api/middleware.py - Middleware setup
from flask import jsonify, request
from datetime import datetime


def setup_error_handlers(app):
    """Setup global error handlers"""

    @app.errorhandler(404)
    def not_found(error):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Endpoint not found",
                    "timestamp": datetime.now().isoformat(),
                }
            ),
            404,
        )

    @app.errorhandler(500)
    def internal_error(error):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Internal server error",
                    "timestamp": datetime.now().isoformat(),
                }
            ),
            500,
        )


def setup_logging_middleware(app, logger):
    """Setup request logging"""

    @app.before_request
    def log_request():
        logger.debug(f"API Request: {request.method} {request.path}")

    @app.after_request
    def log_response(response):
        logger.debug(f"API Response: {response.status_code}")
        return response
