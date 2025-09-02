# src/api/routes/domains.py - Domain management routes
from flask import request
from ..utils import APIResponse, handle_api_errors
from ..validators import DomainValidator


def register_domain_routes(app, deps):
    """Register domain management routes"""

    @app.route("/api/domains", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def list_domains():
        domains = deps["hosting_manager"].list_domains()

        # Add monitoring data to each domain
        for domain in domains:
            domain_name = domain["domain_name"]
            health = deps["health_checker"].get_domain_health(domain_name)
            domain["health"] = health

        return APIResponse.success({"domains": domains, "count": len(domains)})

    @app.route("/api/domains", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def deploy_domain():
        data = request.get_json()

        is_valid, error_msg = DomainValidator.validate_deploy_request(data)
        if not is_valid:
            return APIResponse.bad_request(error_msg)

        domain_name = data["domain_name"]
        port = int(data["port"])
        site_type = data["site_type"]

        success = deps["hosting_manager"].deploy_domain(domain_name, port, site_type)

        if success:
            # Setup health monitoring
            if site_type != "static":
                deps["health_checker"].add_health_check(
                    domain_name, f"http://localhost:{port}"
                )

            return APIResponse.success(
                {
                    "message": f"Domain {domain_name} deployed successfully",
                    "domain": {
                        "domain_name": domain_name,
                        "port": port,
                        "site_type": site_type,
                        "url": f"http://{domain_name}",
                        "monitoring_enabled": True,
                    },
                }
            )
        else:
            return APIResponse.server_error("Domain deployment failed")

    @app.route("/api/domains/<domain_name>", methods=["DELETE"])
    @handle_api_errors(deps["logger"])
    def remove_domain(domain_name):
        # Remove health checks
        deps["health_checker"].remove_health_check(domain_name)

        # Remove domain
        success = deps["hosting_manager"].remove_domain(domain_name)

        if success:
            return APIResponse.success(
                {"message": f"Domain {domain_name} removed successfully"}
            )
        else:
            return APIResponse.server_error("Domain removal failed")
