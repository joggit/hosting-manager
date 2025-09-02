# src/api/routes/next_port_management.py - Port management and Next.js detection routes
from flask import request
import subprocess
import json
import re
import os
from datetime import datetime
from ..utils import APIResponse, handle_api_errors
from ..services import NextPortService


def register_next_port_management_routes(app, deps):
    """Register port management routes"""

    port_service = NextPortService(deps)

    @app.route("/api/ports/nextjs", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_nextjs_ports():
        """Get all ports currently in use by Next.js servers"""
        nextjs_ports = port_service.get_nextjs_port_usage()

        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "nextjs_ports": nextjs_ports,
                "total_nextjs_processes": len(nextjs_ports),
                "port_summary": port_service.get_nextjs_port_summary(nextjs_ports),
            }
        )

    @app.route("/api/ports/listening", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_all_listening_ports():
        """Get all listening ports with process information"""
        listening_ports = port_service.get_all_listening_ports()

        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "listening_ports": listening_ports,
                "total_ports": len(listening_ports),
                "port_ranges": port_service.analyze_port_ranges(listening_ports),
            }
        )

    @app.route("/api/ports/check-range", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def check_port_range():
        """Check port availability in a specific range"""
        data = request.get_json() or {}
        start_port = data.get("startPort", 3000)
        end_port = data.get("endPort", 3100)

        if start_port >= end_port or end_port - start_port > 1000:
            return APIResponse.bad_request(
                "Invalid port range. Maximum range is 1000 ports."
            )

        port_analysis = port_service.check_port_range(start_port, end_port)

        return APIResponse.success(
            {
                "range": f"{start_port}-{end_port}",
                "analysis": port_analysis,
                "timestamp": datetime.now().isoformat(),
            }
        )

    @app.route("/api/ports/suggest", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def suggest_nextjs_ports():
        """Suggest available ports for new Next.js applications"""
        data = request.get_json() or {}
        count = data.get("count", 1)
        preferred_range = data.get("preferredRange", "3000-4000")
        avoid_ports = data.get("avoidPorts", [])

        if count > 50:
            return APIResponse.bad_request("Cannot suggest more than 50 ports at once")

        suggestions = port_service.suggest_available_ports(
            count, preferred_range, avoid_ports
        )

        return APIResponse.success(
            {
                "suggested_ports": suggestions,
                "count_requested": count,
                "count_found": len(suggestions),
                "preferred_range": preferred_range,
                "timestamp": datetime.now().isoformat(),
            }
        )

    @app.route("/api/ports/conflicts", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def detect_port_conflicts():
        """Detect potential port conflicts and issues"""
        conflicts = port_service.detect_port_conflicts()

        return APIResponse.success(
            {
                "conflicts": conflicts,
                "conflict_count": len(conflicts),
                "timestamp": datetime.now().isoformat(),
                "recommendations": port_service.get_conflict_recommendations(conflicts),
            }
        )
