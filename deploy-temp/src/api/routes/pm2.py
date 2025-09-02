# src/api/routes/pm2.py - PM2 management routes
from flask import request
from datetime import datetime
from ..utils import APIResponse, handle_api_errors
from ..validators import DeploymentValidator


def register_pm2_routes(app, deps):
    """Register PM2 management routes"""

    @app.route("/api/deploy/nodejs", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def deploy_nodejs_app():
        data = request.json

        is_valid, error_msg = DeploymentValidator.validate_deploy_request(data)
        if not is_valid:
            return APIResponse.bad_request(error_msg)

        site_name = data["name"]
        project_files = data["files"]
        deploy_config = data.get("deployConfig", {})

        deps["logger"].info(f"Starting deployment for {site_name}")

        # Deploy using process monitor
        result = deps["process_monitor"].deploy_nodejs_app(
            site_name, project_files, deploy_config
        )

        if result["success"]:
            # Setup health monitoring for the new app
            app_port = deploy_config.get("port", 3000)
            deps["health_checker"].add_health_check(
                site_name, f"http://localhost:{app_port}"
            )

        return (
            APIResponse.success(result)
            if result["success"]
            else APIResponse.server_error(result.get("error", "Deployment failed"))
        )

    @app.route("/api/pm2/status", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_pm2_status():
        if not deps["process_monitor"].pm2_available:
            return APIResponse.bad_request("PM2 not available")

        import subprocess

        # Check PM2 daemon
        result = subprocess.run(["pm2", "ping"], capture_output=True, text=True)
        daemon_alive = result.returncode == 0

        # Get PM2 version
        version_result = subprocess.run(
            ["pm2", "--version"], capture_output=True, text=True
        )
        pm2_version = (
            version_result.stdout.strip()
            if version_result.returncode == 0
            else "unknown"
        )

        # Get process count
        processes = deps["process_monitor"].get_pm2_processes()

        return APIResponse.success(
            {
                "pm2": {
                    "daemon_alive": daemon_alive,
                    "version": pm2_version,
                    "process_count": len(processes),
                    "processes_running": len(
                        [
                            p
                            for p in processes
                            if p.get("pm2_env", {}).get("status") == "online"
                        ]
                    ),
                    "timestamp": datetime.now().isoformat(),
                }
            }
        )

    @app.route("/api/pm2/list", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_pm2_processes():
        if not deps["process_monitor"].pm2_available:
            return APIResponse.bad_request("PM2 not available")

        pm2_data = deps["process_monitor"].get_pm2_processes()

        return APIResponse.success(
            {
                "processes": pm2_data,
                "count": len(pm2_data),
                "timestamp": datetime.now().isoformat(),
            }
        )

    @app.route("/api/pm2/<process_name>/<action>", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def pm2_process_action(process_name, action):
        if not deps["process_monitor"].pm2_available:
            return APIResponse.bad_request("PM2 not available")

        valid_actions = ["start", "stop", "restart", "reload", "delete"]
        if action not in valid_actions:
            return APIResponse.bad_request(
                f"Invalid action. Must be one of: {valid_actions}"
            )

        success = deps["process_monitor"].pm2_action(process_name, action)

        if success:
            return APIResponse.success(
                {"message": f"PM2 {action} successful for {process_name}"}
            )
        else:
            return APIResponse.server_error(f"PM2 {action} failed for {process_name}")
