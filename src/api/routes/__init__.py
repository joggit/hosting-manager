# src/api/routes/__init__.py - Safe/lazy route registration
import importlib
import traceback

# List modules (by dotted name under this package) and their register function
ROUTE_MODULES = [
    # ("api.routes.health", "register_health_routes"),
    ("api.routes.processes", "register_process_routes"),
    ("api.routes.domains", "register_domain_routes"),
    ("api.routes.monitoring", "register_monitoring_routes"),
    ("api.routes.pm2", "register_pm2_routes"),
    ("api.routes.nginx", "register_nginx_routes"),
    ("api.routes.logs", "register_log_routes"),
    ("api.routes.utils_routes", "register_utility_routes"),
    ("api.routes.network", "register_network_routes"),
    ("api.routes.next_port_management", "register_next_port_management_routes"),
]


def register_all_routes(app, dependencies):
    """
    Lazily import each route module and register it.
    If one module fails, we log it but continue with others.
    Also stores per-module results in app.config['ROUTE_LOAD_RESULTS'].
    """
    logger = dependencies.get("logger")
    results = {"ok": True, "modules": []}

    for mod_name, func_name in ROUTE_MODULES:
        entry = {"module": mod_name, "func": func_name, "ok": False, "error": None}
        try:
            mod = importlib.import_module(mod_name)
        except Exception as e:
            entry["error"] = f"import failed: {e}"
            results["ok"] = False
            results["modules"].append(entry)
            if logger:
                logger.error(f"[routes] import failed {mod_name}: {e}")
                logger.debug(traceback.format_exc())
            continue

        try:
            register_fn = getattr(mod, func_name, None)
            if not callable(register_fn):
                entry["error"] = f"{func_name} not found/callable in {mod_name}"
                results["ok"] = False
                results["modules"].append(entry)
                if logger:
                    logger.error(f"[routes] missing {func_name} in {mod_name}")
                continue

            register_fn(app, dependencies)
            entry["ok"] = True
            results["modules"].append(entry)
            if logger:
                logger.info(f"[routes] registered: {mod_name}.{func_name}")

        except Exception as e:
            entry["error"] = f"register failed: {e}"
            results["ok"] = False
            results["modules"].append(entry)
            if logger:
                logger.error(f"[routes] register failed {mod_name}.{func_name}: {e}")
                logger.debug(traceback.format_exc())

    app.config["ROUTE_LOAD_RESULTS"] = results
