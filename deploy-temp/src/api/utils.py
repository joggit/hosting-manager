# src/api/utils.py - Utility functions and response helpers
from flask import jsonify
from functools import wraps
import traceback
import socket


class APIResponse:
    """Standardized API response helpers"""

    @staticmethod
    def success(data=None, message=None):
        response = {"success": True}
        if data is not None:
            response.update(data)
        if message:
            response["message"] = message
        return jsonify(response)

    @staticmethod
    def error(message, status_code=500, error_code=None):
        response = {"success": False, "error": message}
        if error_code:
            response["error_code"] = error_code
        return jsonify(response), status_code

    @staticmethod
    def bad_request(message):
        return APIResponse.error(message, 400)

    @staticmethod
    def not_found(message):
        return APIResponse.error(message, 404)

    @staticmethod
    def server_error(message):
        return APIResponse.error(message, 500)


def handle_api_errors(logger):
    """Decorator for consistent error handling"""

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"API error in {f.__name__}: {e}")
                logger.debug(traceback.format_exc())
                return APIResponse.server_error(str(e))

        return wrapper

    return decorator


class PortChecker:
    """Utility class for port checking"""

    @staticmethod
    def is_port_available(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(("localhost", port))
                return result != 0
        except:
            return False

    @staticmethod
    def find_available_ports(start_port, count):
        available_ports = []
        for port in range(start_port, start_port + 100):
            if PortChecker.is_port_available(port):
                available_ports.append(port)
                if len(available_ports) >= count:
                    break

        # Fallback if none found
        if not available_ports:
            available_ports = list(range(3001, 3001 + count))

        return available_ports
