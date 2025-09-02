# src/api/routes/__init__.py - Fixed route registration
import importlib
import traceback

# Simplified route modules - only include working ones
ROUTE_MODULES = [
    ("api.routes.processes", "register_process_routes"),
    ("api.routes.domains", "register_domain_routes"),
    ("api.routes.pm2", "register_pm2_routes"),
    ("api.routes.logs", "register_log_routes"),
    ("api.routes.utils_routes", "register_utility_routes"),
]


def register_all_routes(app, dependencies):
    """Register routes with better error handling"""
    logger = dependencies.get("logger")
    results = {"ok": True, "modules": []}

    # Add a debug route first
    @app.route("/api/_debug/routes/load-status", methods=["GET"])
    def debug_route_status():
        return {"success": True, "results": app.config.get("ROUTE_LOAD_RESULTS", {})}

    for mod_name, func_name in ROUTE_MODULES:
        entry = {"module": mod_name, "func": func_name, "ok": False, "error": None}

        try:
            # Try to import the module
            mod = importlib.import_module(mod_name)
        except Exception as e:
            entry["error"] = f"import failed: {e}"
            results["ok"] = False
            results["modules"].append(entry)
            if logger:
                logger.warning(f"[routes] Failed to import {mod_name}: {e}")
            continue

        try:
            # Try to get and call the register function
            register_fn = getattr(mod, func_name, None)
            if not callable(register_fn):
                entry["error"] = f"{func_name} not found/callable in {mod_name}"
                results["ok"] = False
                results["modules"].append(entry)
                if logger:
                    logger.warning(f"[routes] {func_name} not callable in {mod_name}")
                continue

            # Call the registration function
            register_fn(app, dependencies)
            entry["ok"] = True
            results["modules"].append(entry)
            if logger:
                logger.info(f"[routes] Successfully registered: {mod_name}.{func_name}")

        except Exception as e:
            entry["error"] = f"register failed: {e}"
            results["ok"] = False
            results["modules"].append(entry)
            if logger:
                logger.error(
                    f"[routes] Registration failed {mod_name}.{func_name}: {e}"
                )

    # Store results for debugging
    app.config["ROUTE_LOAD_RESULTS"] = results

    if logger:
        successful = len([m for m in results["modules"] if m["ok"]])
        total = len(results["modules"])
        logger.info(
            f"[routes] Route registration complete: {successful}/{total} modules loaded"
        )
