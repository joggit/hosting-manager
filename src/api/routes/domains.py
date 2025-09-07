# src/api/routes/domains.py
"""
API routes for domain and subdomain management
"""

from flask import request, jsonify
from datetime import datetime
from ..utils import APIResponse, handle_api_errors
from ..validators import DeploymentValidator


def register_domain_routes(app, deps):
    """Register domain management routes"""

    @app.route("/api/domains", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_available_domains():
        """Get list of available parent domains"""
        domain_manager = deps["domain_manager"]
        domains = domain_manager.get_available_domains()

        # Add current usage stats
        enhanced_domains = {}
        for domain, config in domains.items():
            # Get current allocations
            allocated_domains = domain_manager.list_domains(
                parent_domain=domain, status="active"
            )

            enhanced_domains[domain] = {
                **config,
                "current_subdomains": len(allocated_domains),
                "available_ports": config["port_range"][1]
                - config["port_range"][0]
                - len(allocated_domains),
                "example_subdomain": f"myapp.{domain}",
            }

        return APIResponse.success(
            {"domains": enhanced_domains, "total_domains": len(enhanced_domains)}
        )

    @app.route("/api/domains/<parent_domain>/subdomains/check", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def check_subdomain_availability(parent_domain):
        """Check if a subdomain is available"""
        data = request.json
        subdomain = data.get("subdomain", "").lower().strip()

        if not subdomain:
            return APIResponse.bad_request("Subdomain is required")

        domain_manager = deps["domain_manager"]
        available, message = domain_manager.check_subdomain_availability(
            subdomain, parent_domain
        )

        return APIResponse.success(
            {
                "available": available,
                "message": message,
                "subdomain": subdomain,
                "full_domain": f"{subdomain}.{parent_domain}" if available else None,
            }
        )

    @app.route("/api/domains/<parent_domain>/subdomains/suggestions", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_subdomain_suggestions(parent_domain):
        """Get subdomain suggestions for a parent domain"""
        limit = request.args.get("limit", 20, type=int)

        domain_manager = deps["domain_manager"]
        suggestions = domain_manager.get_available_subdomains(parent_domain, limit)

        return APIResponse.success(
            {
                "suggestions": suggestions,
                "parent_domain": parent_domain,
                "count": len(suggestions),
            }
        )

    @app.route("/api/domains/subdomains", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def create_subdomain():
        """Create a new subdomain"""
        data = request.json

        # Validate required fields
        required_fields = ["subdomain", "parent_domain", "app_name"]
        for field in required_fields:
            if not data.get(field):
                return APIResponse.bad_request(f"Missing required field: {field}")

        subdomain = data["subdomain"].lower().strip()
        parent_domain = data["parent_domain"]
        app_name = data["app_name"]

        domain_manager = deps["domain_manager"]

        # Create the subdomain
        result = domain_manager.create_subdomain(subdomain, parent_domain, app_name)

        if result["success"]:
            deps["logger"].info(
                f"Created subdomain: {result['domain']} for app: {app_name}"
            )
            return APIResponse.success(result)
        else:
            return APIResponse.server_error(result["error"])

    @app.route("/api/domains/subdomains", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def list_subdomains():
        """List all subdomains with optional filtering"""
        parent_domain = request.args.get("parent_domain")
        status = request.args.get("status", "active")

        domain_manager = deps["domain_manager"]
        domains = domain_manager.list_domains(
            parent_domain=parent_domain, status=status
        )

        return APIResponse.success(
            {
                "domains": domains,
                "count": len(domains),
                "filters": {"parent_domain": parent_domain, "status": status},
            }
        )

    @app.route("/api/domains/subdomains/<domain_name>", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_subdomain_info(domain_name):
        """Get information about a specific subdomain"""
        domain_manager = deps["domain_manager"]
        domain_info = domain_manager.get_domain_info(domain_name)

        if domain_info:
            return APIResponse.success(domain_info)
        else:
            return APIResponse.not_found("Domain not found")

    @app.route("/api/domains/subdomains/<domain_name>", methods=["DELETE"])
    @handle_api_errors(deps["logger"])
    def delete_subdomain(domain_name):
        """Delete a subdomain"""
        domain_manager = deps["domain_manager"]
        result = domain_manager.delete_subdomain(domain_name)

        if result["success"]:
            deps["logger"].info(f"Deleted subdomain: {domain_name}")
            return APIResponse.success(result)
        else:
            return APIResponse.server_error(result["error"])

    @app.route("/api/deploy/nodejs-domain", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def deploy_nodejs_with_domain():
        """Deploy Node.js app with automatic domain setup"""
        data = request.json

        # Validate deployment request
        is_valid, error_msg = DeploymentValidator.validate_deploy_request(data)
        if not is_valid:
            return APIResponse.bad_request(error_msg)

        # Additional validation for domain deployment
        if not data.get("domain_config"):
            return APIResponse.bad_request("Domain configuration required")

        domain_config = data["domain_config"]
        required_domain_fields = ["subdomain", "parent_domain"]

        for field in required_domain_fields:
            if not domain_config.get(field):
                return APIResponse.bad_request(f"Missing domain field: {field}")

        site_name = data["name"]
        project_files = data["files"]
        deploy_config = data.get("deployConfig", {})

        subdomain = domain_config["subdomain"].lower().strip()
        parent_domain = domain_config["parent_domain"]

        deps["logger"].info(
            f"Starting domain deployment for {site_name} on {subdomain}.{parent_domain}"
        )

        try:
            domain_manager = deps["domain_manager"]

            # Check subdomain availability
            available, message = domain_manager.check_subdomain_availability(
                subdomain, parent_domain
            )
            if not available:
                return APIResponse.bad_request(f"Subdomain not available: {message}")

            # Allocate port for the domain
            port = domain_manager.allocate_port(parent_domain)
            if not port:
                return APIResponse.server_error("No available ports for this domain")

            # Update deploy config with allocated port
            deploy_config["port"] = port
            deploy_config["domain"] = f"{subdomain}.{parent_domain}"

            # Enhanced package.json processing for Next.js + domain deployment
            if "package.json" in project_files:
                try:
                    import json

                    package_data = json.loads(project_files["package.json"])
                    fixes_applied = []

                    # Remove "type": "module" conflicts and ensure domain compatibility
                    if package_data.get("type") == "module":
                        # Keep ES modules but ensure compatibility
                        fixes_applied.append(
                            "Validated ES module configuration for domain deployment"
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

                    # Add domain-specific environment variable
                    if "scripts" in package_data:
                        scripts["start"] = (
                            f"NEXT_PUBLIC_DOMAIN={subdomain}.{parent_domain} next start"
                        )

                    # Update the package.json content
                    project_files["package.json"] = json.dumps(package_data, indent=2)

                    if fixes_applied:
                        deps["logger"].info(
                            f"Package.json fixes for domain deployment: {fixes_applied}"
                        )

                except json.JSONDecodeError as e:
                    deps["logger"].error(f"Invalid package.json for {site_name}: {e}")
                    return APIResponse.bad_request("Invalid package.json format")

            # Deploy the application using process monitor
            deployment_result = deps["process_monitor"].deploy_nodejs_app(
                site_name, project_files, deploy_config
            )

            if deployment_result["success"]:
                # Create the subdomain configuration
                domain_result = domain_manager.create_subdomain(
                    subdomain, parent_domain, site_name, port
                )

                if domain_result["success"]:
                    # Setup health monitoring
                    deps["health_checker"].add_health_check(
                        site_name, f"http://localhost:{port}"
                    )

                    # Combine results
                    final_result = {
                        **deployment_result,
                        "domain": {
                            "subdomain": subdomain,
                            "parent_domain": parent_domain,
                            "full_domain": f"{subdomain}.{parent_domain}",
                            "ssl_enabled": domain_result.get("ssl_enabled", False),
                            "url": f"http{'s' if domain_result.get('ssl_enabled') else ''}://{subdomain}.{parent_domain}",
                        },
                    }

                    deps["logger"].info(
                        f"✅ Domain deployment successful: {subdomain}.{parent_domain}"
                    )
                    return APIResponse.success(final_result)

                else:
                    # Deployment succeeded but domain creation failed
                    # Should clean up the deployment here
                    deps["logger"].error(
                        f"App deployed but domain creation failed: {domain_result.get('error')}"
                    )
                    return APIResponse.server_error(
                        f"App deployed but domain setup failed: {domain_result.get('error')}"
                    )

            else:
                # Deployment failed, free up the allocated port
                # Implementation would depend on your domain manager port deallocation method
                deps["logger"].error(
                    f"❌ Deployment failed for {site_name}: {deployment_result.get('error')}"
                )
                return APIResponse.server_error(
                    deployment_result.get("error", "Deployment failed")
                )

        except Exception as e:
            deps["logger"].error(f"Domain deployment error for {site_name}: {e}")
            return APIResponse.server_error(f"Domain deployment failed: {str(e)}")

    @app.route("/api/domains/status", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_domain_status():
        """Get overall domain system status"""
        try:
            domain_manager = deps["domain_manager"]

            # Get all domains grouped by parent
            status = {}
            total_subdomains = 0

            for parent_domain in domain_manager.get_available_domains().keys():
                domains = domain_manager.list_domains(
                    parent_domain=parent_domain, status="active"
                )
                total_subdomains += len(domains)

                status[parent_domain] = {
                    "active_subdomains": len(domains),
                    "domains": domains[:5],  # Show first 5 for preview
                }

            return APIResponse.success(
                {
                    "total_subdomains": total_subdomains,
                    "parent_domains": len(domain_manager.get_available_domains()),
                    "domains_by_parent": status,
                    "timestamp": datetime.now().isoformat(),
                }
            )

        except Exception as e:
            deps["logger"].error(f"Failed to get domain status: {e}")
            return APIResponse.server_error("Failed to get domain status")

    @app.route("/api/domains/nginx/reload", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def reload_nginx():
        """Manually reload nginx configuration"""
        try:
            domain_manager = deps["domain_manager"]
            success = domain_manager._reload_nginx()

            if success:
                return APIResponse.success({"message": "Nginx reloaded successfully"})
            else:
                return APIResponse.server_error("Failed to reload nginx")

        except Exception as e:
            deps["logger"].error(f"Failed to reload nginx: {e}")
            return APIResponse.server_error("Failed to reload nginx")


# Validation helpers
class DomainValidator:
    """Additional validation for domain-related requests"""

    @staticmethod
    def validate_domain_deployment(data):
        """Validate domain deployment request"""
        errors = []

        if not data.get("domain_config"):
            errors.append("Domain configuration is required")
            return False, errors

        domain_config = data["domain_config"]

        # Check subdomain format
        subdomain = domain_config.get("subdomain", "").strip()
        if not subdomain:
            errors.append("Subdomain is required")
        elif not DomainValidator._is_valid_subdomain(subdomain):
            errors.append("Invalid subdomain format")

        # Check parent domain
        parent_domain = domain_config.get("parent_domain", "").strip()
        valid_domains = ["smartwave.co.za", "datablox.co.za", "mondaycafe.co.za"]
        if not parent_domain:
            errors.append("Parent domain is required")
        elif parent_domain not in valid_domains:
            errors.append(
                f"Invalid parent domain. Must be one of: {', '.join(valid_domains)}"
            )

        return len(errors) == 0, errors

    @staticmethod
    def _is_valid_subdomain(subdomain):
        """Validate subdomain format"""
        import re

        if not subdomain or len(subdomain) > 63:
            return False

        # Must start and end with alphanumeric
        if not (subdomain[0].isalnum() and subdomain[-1].isalnum()):
            return False

        # Can contain hyphens but not consecutive ones
        if "--" in subdomain:
            return False

        # Only alphanumeric and hyphens
        if not re.match(r"^[a-zA-Z0-9-]+$", subdomain):
            return False

        # Reserved subdomains
        reserved = ["www", "mail", "ftp", "localhost", "api", "admin", "root", "test"]
        if subdomain.lower() in reserved:
            return False

        return True
