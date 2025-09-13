# src/api/routes/pm2.py - PM2 management routes with ES module fix
import os
import json
from pathlib import Path
from flask import request
from datetime import datetime
from ..utils import APIResponse, handle_api_errors
from ..validators import DeploymentValidator


def register_pm2_routes(app, deps):
    """Register PM2 management routes"""

    # Enhanced PM2 route with better Next.js handling
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

        deps["logger"].info(f"Starting Next.js deployment for {site_name}")

        # Enhanced package.json processing for Next.js compatibility
        if "package.json" in project_files:
            try:
                package_data = json.loads(project_files["package.json"])
                fixes_applied = []

                # Remove "type": "module" - this is the main cause of the PM2 error
                if package_data.get("type") == "module":
                    del package_data["type"]
                    fixes_applied.append(
                        "Removed 'type: module' for Next.js + PM2 compatibility"
                    )

                # Ensure proper scripts exist
                if "scripts" not in package_data:
                    package_data["scripts"] = {}

                scripts = package_data["scripts"]
                if "build" not in scripts:
                    scripts["build"] = "next build"
                    fixes_applied.append("Added build script")

                if "start" not in scripts:
                    scripts["start"] = "next start"
                    fixes_applied.append("Added start script")

                # Add engines specification for better compatibility
                if "engines" not in package_data:
                    package_data["engines"] = {"node": ">=18.0.0", "npm": ">=8.0.0"}
                    fixes_applied.append("Added engines specification")

                # Update the package.json content
                project_files["package.json"] = json.dumps(package_data, indent=2)

                if fixes_applied:
                    deps["logger"].info(
                        f"Package.json fixes for {site_name}: {fixes_applied}"
                    )

            except json.JSONDecodeError as e:
                deps["logger"].error(f"Invalid package.json for {site_name}: {e}")
                return APIResponse.bad_request("Invalid package.json format")

        # Check for Next.js specific files and add them if missing
        deps["logger"].info(f"Checking Next.js configuration files for {site_name}")

        # Ensure next.config.js exists (without ES modules)
        if (
            "next.config.js" not in project_files
            and "next.config.mjs" not in project_files
        ):
            project_files[
                "next.config.js"
            ] = """/** @type {import('next').NextConfig} */
    const nextConfig = {
    reactStrictMode: true,
    swcMinify: true,
    experimental: {
        esmExternals: false
    },
    images: {
        domains: ['firebasestorage.googleapis.com'],
    },
    };

    module.exports = nextConfig;"""
            deps["logger"].info(f"Added next.config.js for {site_name}")

        # Deploy using enhanced process monitor
        result = deps["process_monitor"].deploy_nodejs_app(
            site_name, project_files, deploy_config
        )

        if result["success"]:
            # Setup health monitoring for the new app
            app_port = deploy_config.get("port", 3000)
            deps["health_checker"].add_health_check(
                site_name, f"http://localhost:{app_port}"
            )
            deps["logger"].info(
                f"✅ Next.js deployment successful for {site_name} on port {app_port}"
            )
        else:
            deps["logger"].error(
                f"❌ Next.js deployment failed for {site_name}: {result.get('error', 'Unknown error')}"
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
