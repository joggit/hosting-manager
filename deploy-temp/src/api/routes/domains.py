# src/api/routes/domains.py - Domain management routes
from flask import jsonify, request
from datetime import datetime


def register_domain_routes(app, deps):
    """Register domain management routes"""
    hosting_manager = deps.get("hosting_manager")
    health_checker = deps.get("health_checker")
    logger = deps.get("logger")

    @app.route("/api/domains", methods=["GET"])
    def list_domains():
        """List all domains"""
        try:
            domains = hosting_manager.list_domains() if hosting_manager else []

            # Add health data if available
            if health_checker:
                for domain in domains:
                    domain_name = domain.get("domain_name")
                    if domain_name:
                        health = health_checker.get_domain_health(domain_name)
                        domain["health"] = health

            return jsonify({"success": True, "domains": domains, "count": len(domains)})
        except Exception as e:
            if logger:
                logger.error(f"Failed to list domains: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/domains", methods=["POST"])
    def deploy_domain():
        """Deploy a new domain"""
        try:
            data = request.get_json()
            if not data or not all(
                k in data for k in ["domain_name", "port", "site_type"]
            ):
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Missing required fields: domain_name, port, site_type",
                        }
                    ),
                    400,
                )

            domain_name = data["domain_name"]
            port = int(data["port"])
            site_type = data["site_type"]

            if not (1 <= port <= 65535):
                return (
                    jsonify(
                        {"success": False, "error": "Port must be between 1 and 65535"}
                    ),
                    400,
                )

            success = (
                hosting_manager.deploy_domain(domain_name, port, site_type)
                if hosting_manager
                else False
            )

            if success:
                return jsonify(
                    {
                        "success": True,
                        "message": f"Domain {domain_name} deployed successfully",
                        "domain": {
                            "domain_name": domain_name,
                            "port": port,
                            "site_type": site_type,
                        },
                    }
                )
            else:
                return (
                    jsonify({"success": False, "error": "Domain deployment failed"}),
                    500,
                )

        except Exception as e:
            if logger:
                logger.error(f"Domain deployment failed: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/domains/<domain_name>", methods=["DELETE"])
    def remove_domain(domain_name):
        """Remove a domain"""
        try:
            success = (
                hosting_manager.remove_domain(domain_name) if hosting_manager else False
            )

            if success:
                return jsonify(
                    {
                        "success": True,
                        "message": f"Domain {domain_name} removed successfully",
                    }
                )
            else:
                return (
                    jsonify({"success": False, "error": "Domain removal failed"}),
                    500,
                )

        except Exception as e:
            if logger:
                logger.error(f"Domain removal failed: {e}")
            return jsonify({"success": False, "error": str(e)}), 500
