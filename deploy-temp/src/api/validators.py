# src/api/validators.py - Request validation
from flask import request


class ProcessValidator:
    """Validate process-related requests"""

    @staticmethod
    def validate_process_name(name):
        if not name or not isinstance(name, str):
            return False, "Process name must be a non-empty string"
        if len(name) > 100:
            return False, "Process name too long"
        # Add more validation as needed
        return True, None


class DomainValidator:
    """Validate domain-related requests"""

    @staticmethod
    def validate_deploy_request(data):
        if not data:
            return False, "Request data is required"

        required_fields = ["domain_name", "port", "site_type"]
        for field in required_fields:
            if field not in data:
                return False, f"Missing required field: {field}"

        # Validate port range
        try:
            port = int(data["port"])
            if not (1 <= port <= 65535):
                return False, "Port must be between 1 and 65535"
        except (ValueError, TypeError):
            return False, "Port must be a valid integer"

        # Validate site type
        if data["site_type"] not in ["static", "api", "node", "app"]:
            return False, "site_type must be one of: static, api, node, app"

        return True, None


class DeploymentValidator:
    """Validate deployment requests"""

    @staticmethod
    def validate_deploy_request(data):
        if not data:
            return False, "Request data is required"

        required = ["name", "files"]
        for field in required:
            if field not in data:
                return False, f"Missing required field: {field}"

        # Validate name
        if not isinstance(data["name"], str) or len(data["name"]) == 0:
            return False, "Name must be a non-empty string"

        # Validate files
        if not isinstance(data["files"], dict):
            return False, "Files must be a dictionary"

        return True, None
