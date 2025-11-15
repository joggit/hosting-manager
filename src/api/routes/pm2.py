# src/api/routes/pm2.py - PM2 management routes with ES module fix
import os
import json
from pathlib import Path
from flask import request
from datetime import datetime
from ..utils import APIResponse, handle_api_errors
from ..validators import DeploymentValidator


def _execute_deployment(data, deps):
    """
    Helper function to execute Node.js deployment
    Used by both /api/deploy/nodejs and /api/deploy/quick-test

    Args:
        data: Deployment data dictionary
        deps: Dependencies dictionary

    Returns:
        Flask response
    """
    # Validate
    is_valid, error_msg = DeploymentValidator.validate_deploy_request(data)
    if not is_valid:
        return APIResponse.bad_request(error_msg)

    site_name = data["name"]
    project_files = data["files"]
    deploy_config = data.get("deployConfig", {})
    domain_config = data.get("domain_config")

    deps["logger"].info(f"═══════════════════════════════════════")
    deps["logger"].info(f"🚀 Starting deployment for {site_name}")
    deps["logger"].info(f"Has domain_config: {domain_config is not None}")

    # ... COPY ALL THE DEPLOYMENT LOGIC FROM deploy_nodejs_app HERE ...
    # (Everything from the existing function except the @app.route decorator)

    # For now, simplified version:
    try:
        # Simplified deployment
        allocated_port = deploy_config.get("port", 3000)

        result = deps["process_monitor"].deploy_nodejs_app(
            site_name, project_files, deploy_config
        )

        if not result["success"]:
            return APIResponse.server_error(result.get("error", "Deployment failed"))

        return APIResponse.success(
            {
                **result,
                "port": allocated_port,
                "domain": domain_config.get("subdomain") if domain_config else None,
            }
        )

    except Exception as e:
        deps["logger"].error(f"Deployment error: {e}")
        return APIResponse.server_error(str(e))


def register_pm2_routes(app, deps):
    """Register PM2 management routes"""

    # Enhanced PM2 route with better Next.js handling
    # Add this to pm2.py - Replace the existing /api/deploy/nodejs endpoint
    @app.route("/api/deploy/nodejs", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def deploy_nodejs_app():
        """
        Unified Node.js deployment endpoint
        Handles: root domains, subdomains, SSL, and regular deployments
        """
        data = request.json
        # Validate basic requirements
        is_valid, error_msg = DeploymentValidator.validate_deploy_request(data)
        if not is_valid:
            return APIResponse.bad_request(error_msg)

        site_name = data["name"]
        project_files = data["files"]
        deploy_config = data.get("deployConfig", {})
        domain_config = data.get("domain_config")  # ← NEW: Optional domain config

        deps["logger"].info(f"═══════════════════════════════════════")
        deps["logger"].info(f"🚀 Starting deployment for {site_name}")
        deps["logger"].info(f"Has domain_config: {domain_config is not None}")
        if domain_config:
            deps["logger"].info(
                f"SSL enabled: {domain_config.get('ssl_enabled', False)}"
            )
            deps["logger"].info(f"SSL email: {domain_config.get('ssl_email', 'N/A')}")
        deps["logger"].info(f"═══════════════════════════════════════")

        # ═══════════════════════════════════════════════════════════
        # STEP 1: Process domain configuration (if provided)
        # ═══════════════════════════════════════════════════════════
        full_domain = None
        deployment_type = "simple"  # simple, subdomain, or root

        if domain_config:
            # Determine domain type
            if domain_config.get("subdomain") and domain_config.get("parent_domain"):
                subdomain = domain_config["subdomain"].lower().strip()
                parent_domain = domain_config["parent_domain"]
                full_domain = f"{subdomain}.{parent_domain}"
                deployment_type = "subdomain"
                deps["logger"].info(f"Subdomain deployment: {full_domain}")

            elif domain_config.get("root_domain"):
                full_domain = domain_config["root_domain"]
                deployment_type = "root"
                deps["logger"].info(f"Root domain deployment: {full_domain}")

            # Validate domain if provided
            if full_domain:
                # Import validation from domains module
                from .domains import PreDeploymentValidator

                validator = PreDeploymentValidator(deps)
                is_valid, validation_results = validator.validate_domain_for_deployment(
                    full_domain
                )

                if not is_valid:
                    error_message = validator.format_validation_error_message(
                        validation_results
                    )
                    deps["logger"].warning(
                        f"Pre-deployment validation failed for {full_domain}"
                    )

                    return APIResponse.bad_request(
                        {
                            "message": f"Cannot deploy {full_domain} - conflicts detected",
                            "error": error_message,
                            "validation_results": validation_results,
                        }
                    )

                deps["logger"].info(f"✅ Domain validation passed for {full_domain}")

        # ═══════════════════════════════════════════════════════════
        # STEP 2: Enhanced package.json processing for Next.js
        # ═══════════════════════════════════════════════════════════
        if "package.json" in project_files:
            try:
                package_data = json.loads(project_files["package.json"])
                fixes_applied = []

                # Remove "type": "module" for PM2 compatibility
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

                # Add engines specification
                if "engines" not in package_data:
                    package_data["engines"] = {"node": ">=18.0.0", "npm": ">=8.0.0"}
                    fixes_applied.append("Added engines specification")

                # Update the package.json content
                project_files["package.json"] = json.dumps(package_data, indent=2)

                if fixes_applied:
                    deps["logger"].info(f"Package.json fixes: {fixes_applied}")

            except json.JSONDecodeError as e:
                deps["logger"].error(f"Invalid package.json: {e}")
                return APIResponse.bad_request("Invalid package.json format")

        # Ensure next.config.js exists
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
            deps["logger"].info("Added next.config.js")

        # ═══════════════════════════════════════════════════════════
        # STEP 3: Port allocation
        # ═══════════════════════════════════════════════════════════
        allocated_port = deploy_config.get("port")

        # If we have a domain with parent domain, try to allocate from range
        if domain_config and deployment_type == "subdomain":
            from .domains import allocate_port_for_deployment, DomainManager

            parent_domain = domain_config["parent_domain"]
            domain_manager = DomainManager(deps["hosting_manager"], deps["logger"])
            port_range = domain_manager.get_port_range_for_domain(parent_domain)

            if port_range:
                allocated_port = allocate_port_for_deployment(
                    preferred_port=allocated_port,
                    start_range=port_range[0],
                    end_range=port_range[1],
                )
                deps["logger"].info(
                    f"Allocated port {allocated_port} from domain range"
                )

        # Fallback to default port if not allocated
        if not allocated_port:
            allocated_port = 3000
            deps["logger"].info(f"Using default port {allocated_port}")

        # Update deploy config with domain info
        if full_domain:
            deploy_config.update(
                {
                    "port": allocated_port,
                    "domain": full_domain,
                    "env": {
                        "PORT": str(allocated_port),
                        "DOMAIN": full_domain,
                        **deploy_config.get("env", {}),
                    },
                }
            )
        else:
            deploy_config["port"] = allocated_port

        # ═══════════════════════════════════════════════════════════
        # STEP 4: Deploy the application
        # ═══════════════════════════════════════════════════════════
        deps["logger"].info(f"Deploying application on port {allocated_port}")

        result = deps["process_monitor"].deploy_nodejs_app(
            site_name, project_files, deploy_config
        )

        if not result["success"]:
            deps["logger"].error(f"❌ Deployment failed: {result.get('error')}")
            return APIResponse.server_error(result.get("error", "Deployment failed"))

        deps["logger"].info(f"✅ Application deployed successfully")

        # ═══════════════════════════════════════════════════════════
        # STEP 5: Create domain entry (if domain config provided)
        # ═══════════════════════════════════════════════════════════
        if full_domain:
            deps["logger"].info(f"Creating domain entry for {full_domain}")

            success = deps["hosting_manager"].deploy_domain(
                domain_name=full_domain,
                port=allocated_port,
                site_type="node",
            )

            if not success:
                deps["logger"].error(f"Failed to create domain entry for {full_domain}")
                # Try to cleanup the deployed app
                try:
                    if hasattr(deps["process_monitor"], "stop_process"):
                        deps["process_monitor"].stop_process(site_name)
                except Exception as cleanup_error:
                    deps["logger"].warning(f"Failed to cleanup: {cleanup_error}")

                return APIResponse.server_error("Domain creation failed")

            deps["logger"].info(f"✅ Domain entry created for {full_domain}")

        # ═══════════════════════════════════════════════════════════
        # STEP 6: Setup health monitoring
        # ═══════════════════════════════════════════════════════════
        try:
            deps["health_checker"].add_health_check(
                site_name, f"http://localhost:{allocated_port}"
            )
            deps["logger"].info(f"✅ Health monitoring configured")
        except Exception as e:
            deps["logger"].warning(f"Could not setup health monitoring: {e}")

        # ═══════════════════════════════════════════════════════════
        # STEP 7: Setup SSL (if requested and domain provided)
        # ═══════════════════════════════════════════════════════════
        ssl_setup_result = None

        if (
            domain_config
            and domain_config.get("ssl_enabled")
            and domain_config.get("ssl_email")
            and full_domain
        ):
            deps["logger"].info(f"🔒 Starting SSL setup for {full_domain}")
            deps["logger"].info(f"SSL Email: {domain_config['ssl_email']}")

            try:
                # Import SSL manager
                from .ssl_manager import create_ssl_manager

                ssl_manager = create_ssl_manager(deps["logger"], deps["config"])

                # Setup SSL certificate
                ssl_success, ssl_message, cert_info = ssl_manager.setup_certificate(
                    full_domain, domain_config["ssl_email"]
                )

                if ssl_success:
                    deps["logger"].info(
                        f"✅ SSL certificate installed successfully for {full_domain}"
                    )

                    ssl_setup_result = {
                        "ssl_enabled": True,
                        "ssl_certificate": cert_info,
                        "ssl_message": ssl_message,
                    }

                    # Update database to mark SSL as enabled
                    try:
                        conn = deps["hosting_manager"].get_database_connection()
                        if conn:
                            cursor = conn.cursor()
                            cursor.execute(
                                "UPDATE domains SET ssl_enabled = 1, updated_at = CURRENT_TIMESTAMP WHERE domain_name = ?",
                                (full_domain,),
                            )
                            conn.commit()
                            conn.close()
                            deps["logger"].info(f"✅ Database updated with SSL status")
                    except Exception as db_err:
                        deps["logger"].warning(
                            f"Could not update SSL status in database: {db_err}"
                        )
                else:
                    deps["logger"].warning(
                        f"⚠️ SSL setup failed for {full_domain}: {ssl_message}"
                    )

                    ssl_setup_result = {"ssl_enabled": False, "ssl_error": ssl_message}

            except Exception as ssl_error:
                deps["logger"].error(
                    f"❌ SSL setup exception for {full_domain}: {ssl_error}"
                )

                ssl_setup_result = {"ssl_enabled": False, "ssl_error": str(ssl_error)}

        # ═══════════════════════════════════════════════════════════
        # STEP 8: Build response
        # ═══════════════════════════════════════════════════════════
        response_data = {
            **result,
            "port": allocated_port,
        }

        # Add domain information if domain config was provided
        if full_domain:
            domain_info = {
                "full_domain": full_domain,
                "domain_type": deployment_type,
                "port": allocated_port,
            }

            # Add SSL information
            if ssl_setup_result:
                domain_info.update(ssl_setup_result)

                # Update URL based on SSL status
                if ssl_setup_result.get("ssl_enabled"):
                    domain_info["url"] = f"https://{full_domain}"
                else:
                    domain_info["url"] = f"http://{full_domain}"
            else:
                domain_info["ssl_enabled"] = False
                domain_info["url"] = f"http://{full_domain}"

            # Add subdomain breakdown if subdomain deployment
            if deployment_type == "subdomain":
                domain_info["subdomain"] = domain_config["subdomain"]
                domain_info["parent_domain"] = domain_config["parent_domain"]

            response_data["domain"] = domain_info

        deps["logger"].info(f"═══════════════════════════════════════")
        deps["logger"].info(f"✅ Deployment completed successfully")
        deps["logger"].info(f"Site: {site_name}")
        deps["logger"].info(f"Port: {allocated_port}")
        if full_domain:
            deps["logger"].info(f"Domain: {full_domain}")
            if ssl_setup_result and ssl_setup_result.get("ssl_enabled"):
                deps["logger"].info(f"SSL: Enabled (https://{full_domain})")
            else:
                deps["logger"].info(f"SSL: Not enabled (http://{full_domain})")
        deps["logger"].info(f"═══════════════════════════════════════")

        return APIResponse.success(response_data)

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

    def _handle_nodejs_deployment(data, deps):
        """
        Internal helper to handle Node.js deployment
        Used by both regular deploy and quick-test endpoints
        """
        # Validate basic requirements
        is_valid, error_msg = DeploymentValidator.validate_deploy_request(data)
        if not is_valid:
            return APIResponse.bad_request(error_msg)

        site_name = data["name"]
        project_files = data["files"]
        deploy_config = data.get("deployConfig", {})
        domain_config = data.get("domain_config")

        deps["logger"].info(f"═══════════════════════════════════════")
        deps["logger"].info(f"🚀 Starting deployment for {site_name}")

        # ... REST OF THE DEPLOYMENT LOGIC FROM deploy_nodejs_app ...
        # (Copy everything from deploy_nodejs_app except the @app.route decorator and first few lines)

    @app.route("/api/deploy/quick-test", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def quick_test_deploy():
        """Quick one-click test deployment"""
        import time

        data = request.json or {}
        timestamp = int(time.time())
        test_name = data.get("name", f"test-{timestamp}")
        test_domain = data.get("domain", f"{test_name}.yourdomain.com")

        deps["logger"].info(f"🚀 Quick test: {test_name} → {test_domain}")

        # Build minimal Next.js files
        test_files = {
            "package.json": json.dumps(
                {
                    "name": test_name,
                    "version": "1.0.0",
                    "scripts": {
                        "dev": "next dev",
                        "build": "next build",
                        "start": "next start",
                    },
                    "dependencies": {
                        "next": "14.2.0",
                        "react": "18.3.0",
                        "react-dom": "18.3.0",
                    },
                }
            ),
            "next.config.js": "module.exports = { reactStrictMode: true };",
            "app/page.js": f"export default function Home() {{ return <div style={{{{minHeight:'100vh',display:'flex',alignItems:'center',justifyContent:'center',background:'linear-gradient(135deg,#667eea,#764ba2)',color:'white',fontFamily:'system-ui'}}}}><h1>🚀 {test_name}</h1></div> }}",
            "app/layout.js": "export default function RootLayout({ children }) { return <html><body>{children}</body></html> }",
        }

        # Parse domain
        parts = test_domain.split(".")
        if len(parts) >= 3:
            domain_config = {
                "subdomain": parts[0],
                "parent_domain": ".".join(parts[1:]),
            }
        else:
            domain_config = {"root_domain": test_domain}

        # Deploy using existing logic
        deploy_request = {
            "name": test_name,
            "files": test_files,
            "domain_config": domain_config,
            "deployConfig": {"env": {"NODE_ENV": "production"}},
        }

        # Temporarily replace request.json
        original_json = request.get_json(silent=True)
        request._cached_json = (deploy_request, deploy_request)

        # Call existing deployment
        result = deploy_nodejs_app()

        # Restore original
        if original_json is not None:
            request._cached_json = (original_json, original_json)

        return result
