# src/api/routes/__init__.py - Route registration
from .health import register_health_routes
from .processes import register_process_routes
from .domains import register_domain_routes
from .monitoring import register_monitoring_routes
from .pm2 import register_pm2_routes
from .nginx import register_nginx_routes
from .logs import register_log_routes
from .utils_routes import register_utility_routes
from .next_port_management import register_next_port_management_routes


def register_all_routes(app, dependencies):
    """Register all API routes"""
    register_health_routes(app, dependencies)
    register_process_routes(app, dependencies)
    register_domain_routes(app, dependencies)
    register_monitoring_routes(app, dependencies)
    register_pm2_routes(app, dependencies)
    register_nginx_routes(app, dependencies)
    register_log_routes(app, dependencies)
    register_utility_routes(app, dependencies)
    register_next_port_management_routes(app, dependencies)
