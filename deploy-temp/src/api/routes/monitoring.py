# src/api/routes/monitoring.py - Monitoring routes
from flask import request
from datetime import datetime
from ..utils import APIResponse, handle_api_errors
from ..services import MonitoringService, AlertService, NginxAuditService


def register_monitoring_routes(app, deps):
    """Register monitoring routes"""

    monitoring_service = MonitoringService(deps)
    alert_service = AlertService(deps)

    @app.route("/api/monitoring/health", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_health_status():
        health_data = deps["health_checker"].get_all_health_data()

        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "health_checks": health_data,
                "summary": {
                    "total_checks": len(health_data),
                    "healthy_count": len(
                        [h for h in health_data if h["status"] == "healthy"]
                    ),
                    "unhealthy_count": len(
                        [h for h in health_data if h["status"] == "unhealthy"]
                    ),
                },
            }
        )

    @app.route("/api/monitoring/metrics", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_system_metrics():
        metrics = deps["process_monitor"].get_system_metrics()

        return APIResponse.success(
            {
                "timestamp": datetime.now().isoformat(),
                "metrics": metrics,
            }
        )

    @app.route("/api/monitoring/dashboard", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_dashboard_overview():
        dashboard_data = monitoring_service.get_dashboard_data()

        return APIResponse.success(
            {
                "dashboard": dashboard_data,
                "last_updated": datetime.now().isoformat(),
            }
        )

    @app.route("/api/monitoring/sites", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_all_sites_status():
        sites_data = monitoring_service.get_all_sites_status()

        # Sort by status (unhealthy first, then by name)
        sites_data.sort(
            key=lambda x: (x["overall_status"] != "healthy", x["domain_name"])
        )

        return APIResponse.success(
            {
                "sites": sites_data,
                "total_sites": len(sites_data),
                "healthy_sites": len(
                    [s for s in sites_data if s["overall_status"] == "healthy"]
                ),
                "timestamp": datetime.now().isoformat(),
            }
        )

    @app.route("/api/monitoring/sites/<site_name>", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_site_detailed_monitoring(site_name):
        site_data = monitoring_service.get_site_detailed_status(site_name)

        return APIResponse.success({"site": site_data})

    @app.route("/api/monitoring/system/resources", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_system_resources():
        resources = monitoring_service.get_system_resources()

        return APIResponse.success({"resources": resources})

    @app.route("/api/monitoring/alerts", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_active_alerts():
        alerts = alert_service.generate_alerts()

        return APIResponse.success(
            {
                "alerts": alerts,
                "alert_count": len(alerts),
                "critical_count": len(
                    [a for a in alerts if a["severity"] == "critical"]
                ),
                "warning_count": len([a for a in alerts if a["severity"] == "warning"]),
                "timestamp": datetime.now().isoformat(),
            }
        )

    @app.route("/api/monitoring/logs/stream/<site_name>", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def stream_site_logs(site_name):
        lines = int(request.args.get("lines", 100))
        logs = deps["process_monitor"].get_process_logs(site_name, lines)

        return APIResponse.success(
            {
                "logs": logs,
                "site_name": site_name,
                "timestamp": datetime.now().isoformat(),
            }
        )

    # Audit endpoints
    @app.route("/api/monitoring/audit/quick", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def audit_quick():
        audit_service = NginxAuditService(deps)
        audit = audit_service.audit_nginx_pm2()
        cross = audit.get("crosscheck", [])
        summary = []

        for c in cross:
            names = c.get("server_names") or [str(c.get("file", "")).split("/")[-1]]
            summary.append(
                {
                    "domain": ", ".join(names),
                    "type": c.get("type"),
                    "root": c.get("root"),
                    "port": c.get("port"),
                    "listening": c.get("listening"),
                    "pm2_app": c.get("pm2_app"),
                }
            )

        return APIResponse.success(
            {
                "summary": summary,
                "ts": datetime.now().isoformat(),
            }
        )

    @app.route("/api/monitoring/audit/sites", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def audit_sites():
        audit_service = NginxAuditService(deps)
        audit = audit_service.audit_nginx_pm2()
        audit["ts"] = datetime.now().isoformat()

        return APIResponse.success({"audit": audit})
