# src/api/routes/processes.py - Process management routes
from flask import request
from datetime import datetime
from ..utils import APIResponse, handle_api_errors
from ..validators import ProcessValidator


def register_process_routes(app, deps):
    """Register process management routes"""

    @app.route("/api/processes", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_all_processes():
        deps["logger"].debug("API /api/processes called")

        processes = deps["process_monitor"].get_all_processes()
        summary = deps["process_monitor"].get_process_summary()

        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "summary": summary,
                "processes": processes,
                "monitoring": {
                    "pm2_available": deps["process_monitor"].pm2_available,
                    "total_memory": summary.get("total_memory_mb", 0),
                    "average_cpu": summary.get("average_cpu", 0.0),
                },
            }
        )

    @app.route("/api/processes/<process_name>", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_process_details(process_name):
        is_valid, error_msg = ProcessValidator.validate_process_name(process_name)
        if not is_valid:
            return APIResponse.bad_request(error_msg)

        process_info = deps["process_monitor"].get_process_details(process_name)

        if not process_info:
            return APIResponse.not_found("Process not found")

        # Add health data
        health_data = deps["health_checker"].get_process_health(process_name)
        process_info["health"] = health_data

        return APIResponse.success({"process": process_info})

    @app.route("/api/processes/<process_name>/start", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def start_process(process_name):
        success = deps["process_monitor"].start_process(process_name)

        if success:
            return APIResponse.success({"message": f"Process {process_name} started"})
        else:
            return APIResponse.server_error(f"Failed to start process {process_name}")

    @app.route("/api/processes/<process_name>/stop", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def stop_process(process_name):
        success = deps["process_monitor"].stop_process(process_name)

        if success:
            return APIResponse.success({"message": f"Process {process_name} stopped"})
        else:
            return APIResponse.server_error(f"Failed to stop process {process_name}")

    @app.route("/api/processes/<process_name>/restart", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def restart_process(process_name):
        success = deps["process_monitor"].restart_process(process_name)

        if success:
            return APIResponse.success({"message": f"Process {process_name} restarted"})
        else:
            return APIResponse.server_error(f"Failed to restart process {process_name}")

    @app.route("/api/processes/<process_name>/logs", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_process_logs(process_name):
        lines = int(request.args.get("lines", 50))
        logs = deps["process_monitor"].get_process_logs(process_name, lines)

        return APIResponse.success(
            {
                "logs": logs,
                "process_name": process_name,
                "lines_requested": lines,
            }
        )
