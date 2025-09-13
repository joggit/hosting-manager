# utils/port_checker.py - Real-time port availability checking

import subprocess
import socket
import logging
from typing import List, Dict, Set

logger = logging.getLogger(__name__)


class PortChecker:
    def __init__(self):
        self.preferred_method = self._detect_best_method()

    def _detect_best_method(self) -> str:
        """Detect the best available method for checking ports"""
        try:
            # Try netstat first
            subprocess.run(["netstat", "--version"], capture_output=True, check=True)
            return "netstat"
        except (subprocess.CalledProcessError, FileNotFoundError):
            try:
                # Try ss command (modern alternative to netstat)
                subprocess.run(["ss", "--version"], capture_output=True, check=True)
                return "ss"
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Fallback to socket method
                return "socket"

    def is_port_in_use(self, port: int, host: str = "localhost") -> bool:
        """
        Check if a specific port is in use

        Args:
            port: Port number to check
            host: Host to check (default: localhost)

        Returns:
            bool: True if port is in use, False if available
        """
        try:
            if self.preferred_method == "netstat":
                return self._check_port_netstat(port)
            elif self.preferred_method == "ss":
                return self._check_port_ss(port)
            else:
                return self._check_port_socket(port, host)
        except Exception as e:
            logger.error(f"Error checking port {port}: {e}")
            # Fallback to socket method if system command fails
            return self._check_port_socket(port, host)

    def _check_port_netstat(self, port: int) -> bool:
        """Check port using netstat command"""
        try:
            # Check both TCP and UDP
            cmd = ["netstat", "-tulpn"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                raise Exception(f"netstat failed: {result.stderr}")

            # Look for the port in the output
            lines = result.stdout.split("\n")
            for line in lines:
                if f":{port} " in line and ("LISTEN" in line or "UDP" in line):
                    return True
            return False

        except Exception as e:
            logger.warning(f"netstat check failed for port {port}: {e}")
            raise

    def _check_port_ss(self, port: int) -> bool:
        """Check port using ss command (modern netstat alternative)"""
        try:
            # Check both TCP and UDP listening ports
            cmd = ["ss", "-tulpn"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                raise Exception(f"ss command failed: {result.stderr}")

            # Look for the port in the output
            lines = result.stdout.split("\n")
            for line in lines:
                if f":{port} " in line and ("LISTEN" in line or "UNCONN" in line):
                    return True
            return False

        except Exception as e:
            logger.warning(f"ss check failed for port {port}: {e}")
            raise

    def _check_port_socket(self, port: int, host: str = "localhost") -> bool:
        """Check port using socket connection (fallback method)"""
        try:
            # Try to bind to the port
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                result = sock.bind((host, port))
                return False  # If we can bind, port is available
        except OSError:
            # If we can't bind, port is in use
            return True

    def get_available_ports(
        self, start_port: int = 3001, count: int = 100, exclude_ports: Set[int] = None
    ) -> List[int]:
        """
        Get a list of available ports in a range

        Args:
            start_port: Starting port number
            count: Number of ports to check
            exclude_ports: Set of ports to exclude from results

        Returns:
            List[int]: List of available port numbers
        """
        available_ports = []
        exclude_ports = exclude_ports or set()

        for port in range(start_port, start_port + count):
            if port in exclude_ports:
                continue

            try:
                if not self.is_port_in_use(port):
                    available_ports.append(port)
            except Exception as e:
                logger.warning(f"Failed to check port {port}: {e}")
                continue

        return available_ports

    def get_port_info(self, port: int) -> Dict:
        """
        Get detailed information about a port

        Args:
            port: Port number to investigate

        Returns:
            Dict: Port information including process details if available
        """
        try:
            if self.preferred_method in ["netstat", "ss"]:
                return self._get_port_info_system(port)
            else:
                return self._get_port_info_socket(port)
        except Exception as e:
            logger.error(f"Error getting port info for {port}: {e}")
            return {
                "port": port,
                "in_use": self.is_port_in_use(port),
                "process": None,
                "error": str(e),
            }

    def _get_port_info_system(self, port: int) -> Dict:
        """Get port info using system commands"""
        cmd = (
            ["netstat", "-tulpn"]
            if self.preferred_method == "netstat"
            else ["ss", "-tulpn"]
        )

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            lines = result.stdout.split("\n")

            for line in lines:
                if f":{port} " in line:
                    parts = line.split()
                    if len(parts) >= 6:
                        return {
                            "port": port,
                            "in_use": True,
                            "protocol": parts[0],
                            "address": parts[3],
                            "state": parts[5] if len(parts) > 5 else "UNKNOWN",
                            "process": parts[6] if len(parts) > 6 else "UNKNOWN",
                        }

            return {"port": port, "in_use": False, "process": None}

        except Exception as e:
            raise Exception(f"System command failed: {e}")

    def _get_port_info_socket(self, port: int) -> Dict:
        """Get port info using socket method"""
        return {
            "port": port,
            "in_use": self.is_port_in_use(port),
            "process": None,  # Socket method doesn't provide process info
            "method": "socket",
        }


# API endpoint integration
from flask import Flask, request, jsonify

app = Flask(__name__)
port_checker = PortChecker()


@app.route("/api/check-ports", methods=["POST"])
def check_ports():
    """API endpoint to check port availability"""
    try:
        data = request.get_json()
        start_port = data.get("startPort", 3001)
        count = data.get("count", 100)
        exclude_ports = set(data.get("excludePorts", []))

        # Get available ports
        available_ports = port_checker.get_available_ports(
            start_port=start_port, count=count, exclude_ports=exclude_ports
        )

        return jsonify(
            {
                "success": True,
                "availablePorts": available_ports,
                "totalChecked": count,
                "totalAvailable": len(available_ports),
                "method": port_checker.preferred_method,
            }
        )

    except Exception as e:
        logger.error(f"Port check API error: {e}")
        return jsonify({"success": False, "error": str(e), "availablePorts": []}), 500


@app.route("/api/check-port/<int:port>", methods=["GET"])
def check_single_port(port):
    """Check if a specific port is available"""
    try:
        port_info = port_checker.get_port_info(port)

        return jsonify(
            {
                "success": True,
                "port": port,
                "available": not port_info["in_use"],
                "details": port_info,
            }
        )

    except Exception as e:
        logger.error(f"Single port check error: {e}")
        return (
            jsonify(
                {"success": False, "error": str(e), "port": port, "available": False}
            ),
            500,
        )


@app.route("/api/port-health", methods=["GET"])
def port_health():
    """Get overall port system health"""
    try:
        # Check a few test ports to verify the system is working
        test_ports = [22, 80, 443]  # SSH, HTTP, HTTPS - likely to be in use
        test_results = {}

        for port in test_ports:
            test_results[port] = port_checker.is_port_in_use(port)

        return jsonify(
            {
                "success": True,
                "method": port_checker.preferred_method,
                "testResults": test_results,
                "systemWorking": True,
            }
        )

    except Exception as e:
        logger.error(f"Port health check error: {e}")
        return jsonify({"success": False, "error": str(e), "systemWorking": False}), 500


# Usage example for deployment
def allocate_port_for_deployment(
    preferred_port: int = None, start_range: int = 3001, end_range: int = 4000
) -> int:
    """
    Allocate a port for deployment

    Args:
        preferred_port: Preferred port number (if available)
        start_range: Start of port range to search
        end_range: End of port range to search

    Returns:
        int: Available port number

    Raises:
        Exception: If no ports available
    """
    checker = PortChecker()

    # Check preferred port first
    if preferred_port and start_range <= preferred_port <= end_range:
        if not checker.is_port_in_use(preferred_port):
            logger.info(f"Allocated preferred port {preferred_port}")
            return preferred_port
        else:
            logger.warning(f"Preferred port {preferred_port} is in use")

    # Find any available port in range
    available_ports = checker.get_available_ports(
        start_port=start_range, count=(end_range - start_range + 1)
    )

    if not available_ports:
        raise Exception(f"No available ports in range {start_range}-{end_range}")

    allocated_port = available_ports[0]
    logger.info(f"Allocated port {allocated_port}")
    return allocated_port


if __name__ == "__main__":
    # Test the port checker
    checker = PortChecker()

    print(f"Using method: {checker.preferred_method}")

    # Test some common ports
    test_ports = [22, 80, 443, 3000, 3001, 3002]
    for port in test_ports:
        in_use = checker.is_port_in_use(port)
        print(f"Port {port}: {'IN USE' if in_use else 'AVAILABLE'}")

    # Get available ports in range
    available = checker.get_available_ports(3001, 10)
    print(f"Available ports in range 3001-3010: {available}")
