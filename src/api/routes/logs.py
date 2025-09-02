# src/api/routes/logs.py - Log management routes
from flask import request
from ..utils import APIResponse, handle_api_errors


def register_log_routes(app, deps):
    """Register log management routes"""

    @app.route("/api/logs", methods=["GET"])
    @handle_api_errors(deps["logger"])
    def get_deployment_logs():
        limit = request.args.get("limit", 100, type=int)
        domain_filter = request.args.get("domain")
        action_filter = request.args.get("action")

        conn = deps["hosting_manager"].get_database_connection()
        if not conn:
            return APIResponse.server_error("Database connection failed")

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

        return APIResponse.success(
            {
                "logs": logs,
                "count": len(logs),
                "filters": {
                    "domain": domain_filter,
                    "action": action_filter,
                    "limit": limit,
                },
            }
        )
