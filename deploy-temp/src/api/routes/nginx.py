# src/api/routes/nginx.py - Nginx information routes
from ..utils import APIResponse, handle_api_errors
from ..services import NginxService


def register_nginx_routes(app, deps):
    """Register nginx information routes"""

    nginx_service = NginxService(deps)

    @app.route("/api/nginx/status", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_nginx_status():
        nginx_info = nginx_service.get_comprehensive_status()

        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "nginx": nginx_info,
            }
        )

    @app.route("/api/nginx/sites-enabled", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_nginx_enabled_sites():
        enabled_sites = nginx_service.get_enabled_sites()

        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "enabled_sites": enabled_sites,
                "count": len(enabled_sites),
            }
        )

    @app.route("/api/sites", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_all_sites_detailed():
        sites_info = nginx_service.get_comprehensive_sites_info()

        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "server_info": nginx_service.get_server_info(),
                "sites": sites_info,
                "summary": {
                    "total_sites": len(sites_info),
                    "active_sites": len(
                        [s for s in sites_info if s["status"] == "active"]
                    ),
                    "ssl_enabled_sites": len(
                        [s for s in sites_info if s.get("ssl_enabled", False)]
                    ),
                    "static_sites": len(
                        [s for s in sites_info if s.get("site_type") == "static"]
                    ),
                    "dynamic_sites": len(
                        [s for s in sites_info if s.get("site_type") != "static"]
                    ),
                },
            }
        )

    @app.route("/api/sites/<domain_name>/details", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_site_details(domain_name):
        site_info = nginx_service.get_site_detailed_info(domain_name)

        if not site_info:
            return APIResponse.not_found("Site not found")

        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "site": site_info,
            }
        )

    @app.route("/api/sites/<domain_name>/nginx-config", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_site_nginx_config(domain_name):
        config_content = nginx_service.get_nginx_config_content(domain_name)
        config_info = nginx_service.get_nginx_config_info(domain_name)

        if not config_content:
            return APIResponse.not_found("Nginx config not found")

        return APIResponse.success(
            {
                "domain_name": domain_name,
                "config_info": config_info,
                "config_content": config_content,
                "parsed_config": nginx_service.parse_nginx_config_content(
                    config_content
                ),
            }
        )

    @app.route("/api/sites/connectivity", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def test_sites_connectivity():
        connectivity_results = nginx_service.test_all_sites_connectivity()

        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "connectivity_tests": connectivity_results,
                "summary": {
                    "total_tested": len(connectivity_results),
                    "responding": len(
                        [r for r in connectivity_results if r["responding"]]
                    ),
                    "not_responding": len(
                        [r for r in connectivity_results if not r["responding"]]
                    ),
                },
            }
        )

    @app.route("/api/server/network-info", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_server_network_info():
        network_info = nginx_service.get_comprehensive_network_info()

        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "network": network_info,
            }
        )
