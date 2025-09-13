# src/api/routes/logs.py
"""
Logs and deployment history API routes
"""

import functools
from flask import request, jsonify
from datetime import datetime


def handle_api_errors(logger):
    """Error handling decorator"""

    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"API error in {f.__name__}: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        return wrapper

    return decorator


def register_log_routes(app, deps):
    """Register logs and deployment history routes"""

    logger = deps.get("logger")
    hosting_manager = deps.get("hosting_manager")

    if not logger:
        print("ERROR: Logger not available for log routes")
        return False

    logger.info("Registering log routes...")

    @app.route("/api/logs", methods=["GET"])
    @handle_api_errors(logger)
    def get_deployment_logs():
        """Get deployment logs with filtering"""
        try:
            limit = request.args.get("limit", 100, type=int)
            domain_filter = request.args.get("domain")
            action_filter = request.args.get("action")
            status_filter = request.args.get("status")

            if not hosting_manager:
                return jsonify(
                    {
                        "success": True,
                        "logs": [],
                        "count": 0,
                        "filters": {
                            "domain": domain_filter,
                            "action": action_filter,
                            "status": status_filter,
                            "limit": limit,
                        },
                        "message": "Hosting manager not available",
                    }
                )

            conn = hosting_manager.get_database_connection()
            if not conn:
                return (
                    jsonify({"success": False, "error": "Database connection failed"}),
                    500,
                )

            cursor = conn.cursor()

            # Build query based on filters
            where_clauses = []
            params = []

            if domain_filter:
                where_clauses.append("domain_name = ?")
                params.append(domain_filter)

            if action_filter:
                where_clauses.append("action = ?")
                params.append(action_filter)

            if status_filter:
                where_clauses.append("status = ?")
                params.append(status_filter)

            where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""
            params.append(limit)

            cursor.execute(
                f"""
                SELECT domain_name, action, status, message, details, created_at
                FROM deployment_logs 
                {where_sql}
                ORDER BY created_at DESC
                LIMIT ?
            """,
                params,
            )

            logs = []
            for row in cursor.fetchall():
                logs.append(
                    {
                        "domain_name": row[0],
                        "action": row[1],
                        "status": row[2],
                        "message": row[3],
                        "details": row[4],
                        "created_at": row[5],
                    }
                )

            conn.close()

            return jsonify(
                {
                    "success": True,
                    "logs": logs,
                    "count": len(logs),
                    "filters": {
                        "domain": domain_filter,
                        "action": action_filter,
                        "status": status_filter,
                        "limit": limit,
                    },
                    "timestamp": datetime.now().isoformat(),
                }
            )

        except Exception as e:
            logger.error(f"Failed to get logs: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/logs/recent", methods=["GET"])
    @handle_api_errors(logger)
    def get_recent_logs():
        """Get recent system logs"""
        try:
            lines = request.args.get("lines", 50, type=int)

            # Try to get recent logs from the logger
            recent_logs = []

            if hasattr(logger, "get_recent_logs"):
                try:
                    recent_logs = logger.get_recent_logs(lines)
                except Exception as e:
                    logger.warning(f"Failed to get recent logs from logger: {e}")

            return jsonify(
                {
                    "success": True,
                    "logs": recent_logs,
                    "lines_requested": lines,
                    "timestamp": datetime.now().isoformat(),
                    "source": "system",
                }
            )

        except Exception as e:
            logger.error(f"Failed to get recent system logs: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/logs/domains/<domain_name>", methods=["GET"])
    @handle_api_errors(logger)
    def get_domain_logs(domain_name):
        """Get logs for a specific domain"""
        try:
            limit = request.args.get("limit", 50, type=int)
            action_filter = request.args.get("action")

            if not hosting_manager:
                return jsonify(
                    {
                        "success": True,
                        "logs": [],
                        "count": 0,
                        "domain": domain_name,
                        "message": "Hosting manager not available",
                    }
                )

            conn = hosting_manager.get_database_connection()
            if not conn:
                return (
                    jsonify({"success": False, "error": "Database connection failed"}),
                    500,
                )

            cursor = conn.cursor()

            # Build query
            where_clauses = ["domain_name = ?"]
            params = [domain_name]

            if action_filter:
                where_clauses.append("action = ?")
                params.append(action_filter)

            params.append(limit)

            cursor.execute(
                f"""
                SELECT domain_name, action, status, message, details, created_at
                FROM deployment_logs 
                WHERE {' AND '.join(where_clauses)}
                ORDER BY created_at DESC
                LIMIT ?
            """,
                params,
            )

            logs = []
            for row in cursor.fetchall():
                logs.append(
                    {
                        "domain_name": row[0],
                        "action": row[1],
                        "status": row[2],
                        "message": row[3],
                        "details": row[4],
                        "created_at": row[5],
                    }
                )

            conn.close()

            return jsonify(
                {
                    "success": True,
                    "logs": logs,
                    "count": len(logs),
                    "domain": domain_name,
                    "filters": {
                        "action": action_filter,
                        "limit": limit,
                    },
                    "timestamp": datetime.now().isoformat(),
                }
            )

        except Exception as e:
            logger.error(f"Failed to get domain logs: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/logs/actions/<action_name>", methods=["GET"])
    @handle_api_errors(logger)
    def get_action_logs(action_name):
        """Get logs for a specific action type"""
        try:
            limit = request.args.get("limit", 50, type=int)
            status_filter = request.args.get("status")

            if not hosting_manager:
                return jsonify(
                    {
                        "success": True,
                        "logs": [],
                        "count": 0,
                        "action": action_name,
                        "message": "Hosting manager not available",
                    }
                )

            conn = hosting_manager.get_database_connection()
            if not conn:
                return (
                    jsonify({"success": False, "error": "Database connection failed"}),
                    500,
                )

            cursor = conn.cursor()

            # Build query
            where_clauses = ["action = ?"]
            params = [action_name]

            if status_filter:
                where_clauses.append("status = ?")
                params.append(status_filter)

            params.append(limit)

            cursor.execute(
                f"""
                SELECT domain_name, action, status, message, details, created_at
                FROM deployment_logs 
                WHERE {' AND '.join(where_clauses)}
                ORDER BY created_at DESC
                LIMIT ?
            """,
                params,
            )

            logs = []
            for row in cursor.fetchall():
                logs.append(
                    {
                        "domain_name": row[0],
                        "action": row[1],
                        "status": row[2],
                        "message": row[3],
                        "details": row[4],
                        "created_at": row[5],
                    }
                )

            conn.close()

            return jsonify(
                {
                    "success": True,
                    "logs": logs,
                    "count": len(logs),
                    "action": action_name,
                    "filters": {
                        "status": status_filter,
                        "limit": limit,
                    },
                    "timestamp": datetime.now().isoformat(),
                }
            )

        except Exception as e:
            logger.error(f"Failed to get action logs: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/logs/stats", methods=["GET"])
    @handle_api_errors(logger)
    def get_log_stats():
        """Get deployment log statistics"""
        try:
            if not hosting_manager:
                return jsonify(
                    {
                        "success": True,
                        "stats": {
                            "total_logs": 0,
                            "actions": {},
                            "statuses": {},
                            "domains": {},
                        },
                        "message": "Hosting manager not available",
                    }
                )

            conn = hosting_manager.get_database_connection()
            if not conn:
                return (
                    jsonify({"success": False, "error": "Database connection failed"}),
                    500,
                )

            cursor = conn.cursor()

            # Get total count
            cursor.execute("SELECT COUNT(*) FROM deployment_logs")
            total_logs = cursor.fetchone()[0]

            # Get action counts
            cursor.execute(
                """
                SELECT action, COUNT(*) 
                FROM deployment_logs 
                GROUP BY action
                ORDER BY COUNT(*) DESC
            """
            )
            actions = dict(cursor.fetchall())

            # Get status counts
            cursor.execute(
                """
                SELECT status, COUNT(*) 
                FROM deployment_logs 
                GROUP BY status
                ORDER BY COUNT(*) DESC
            """
            )
            statuses = dict(cursor.fetchall())

            # Get top domains
            cursor.execute(
                """
                SELECT domain_name, COUNT(*) 
                FROM deployment_logs 
                GROUP BY domain_name
                ORDER BY COUNT(*) DESC
                LIMIT 10
            """
            )
            domains = dict(cursor.fetchall())

            conn.close()

            return jsonify(
                {
                    "success": True,
                    "stats": {
                        "total_logs": total_logs,
                        "actions": actions,
                        "statuses": statuses,
                        "top_domains": domains,
                    },
                    "timestamp": datetime.now().isoformat(),
                }
            )

        except Exception as e:
            logger.error(f"Failed to get log stats: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/logs/clear", methods=["POST"])
    @handle_api_errors(logger)
    def clear_old_logs():
        """Clear old deployment logs"""
        try:
            days = request.json.get("days", 30) if request.json else 30

            if not hosting_manager:
                return (
                    jsonify(
                        {"success": False, "error": "Hosting manager not available"}
                    ),
                    500,
                )

            conn = hosting_manager.get_database_connection()
            if not conn:
                return (
                    jsonify({"success": False, "error": "Database connection failed"}),
                    500,
                )

            cursor = conn.cursor()

            # Delete logs older than specified days
            cursor.execute(
                """
                DELETE FROM deployment_logs 
                WHERE created_at < datetime('now', '-' || ? || ' days')
            """,
                (days,),
            )

            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()

            return jsonify(
                {
                    "success": True,
                    "message": f"Cleared {deleted_count} logs older than {days} days",
                    "deleted_count": deleted_count,
                    "days": days,
                    "timestamp": datetime.now().isoformat(),
                }
            )

        except Exception as e:
            logger.error(f"Failed to clear logs: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    logger.info("Log routes registered successfully")
    return True
