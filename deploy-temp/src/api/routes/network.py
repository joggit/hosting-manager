# src/api/routes/network.py
from flask import request, jsonify
from datetime import datetime
import psutil
import socket  # ← use socket.SOCK_STREAM / SOCK_DGRAM
import subprocess
import traceback


def register_network_routes(app, dependencies):
    logger = dependencies.get("logger")

    @app.route("/api/network/ports", methods=["GET"])
    def list_tcp_ports():
        """
        List TCP (and optionally UDP) ports in use with owning process info.

        Query params (optional):
          - include_udp=true|false      (default false)
          - listening_only=true|false  (default true; only listeners)
          - state=LISTEN,ESTABLISHED   (CSV of states to include; applies to TCP)
          - port=3000,3001-3010        (CSV; supports ranges)
          - process=node               (substring filter on process name/cmd)
        """
        try:
            include_udp = request.args.get("include_udp", "false").lower() == "true"
            listening_only = (
                request.args.get("listening_only", "true").lower() == "true"
            )

            # state filter (TCP states like LISTEN, ESTABLISHED)
            state_raw = request.args.get("state", "")
            state_filter = {
                s.strip().upper() for s in state_raw.split(",") if s.strip()
            }

            # port filter (single values and ranges)
            ports_wanted = None
            port_raw = request.args.get("port")
            if port_raw:
                ports_wanted = set()
                for tok in port_raw.split(","):
                    tok = tok.strip()
                    if not tok:
                        continue
                    if "-" in tok:
                        a, b = tok.split("-", 1)
                        try:
                            a, b = int(a), int(b)
                            lo, hi = min(a, b), max(a, b)
                            ports_wanted.update(range(lo, hi + 1))
                        except Exception:
                            pass
                    else:
                        try:
                            ports_wanted.add(int(tok))
                        except Exception:
                            pass

            proc_filter = request.args.get("process", "").strip().lower() or None

            # Collect inet connections once
            conns = psutil.net_connections(kind="inet")

            rows = []
            by_status = {}
            listening_ports = set()
            by_proc_counts = {}

            for c in conns:
                # Map proto via socket constants (NOT psutil)
                if c.type == socket.SOCK_STREAM:
                    proto = "tcp"
                elif c.type == socket.SOCK_DGRAM:
                    proto = "udp"
                else:
                    # Unknown/other; skip
                    continue

                if proto == "udp" and not include_udp:
                    continue

                status = (
                    c.status or "NONE"
                )  # e.g., 'LISTEN', 'ESTABLISHED', or 'NONE' for UDP

                laddr = c.laddr if c.laddr else None
                raddr = c.raddr if c.raddr else None
                lport = getattr(laddr, "port", None)

                # Filters
                if ports_wanted and lport not in ports_wanted:
                    continue
                if (
                    state_filter
                    and proto == "tcp"
                    and status.upper() not in state_filter
                ):
                    continue

                # "listening_only" semantics:
                # - TCP: include only LISTEN
                # - UDP: treat sockets with no raddr as "listeners"
                if listening_only:
                    if proto == "tcp" and status != "LISTEN":
                        continue
                    if proto == "udp" and raddr:  # has remote peer => not "listener"
                        continue

                pid = c.pid
                name = username = cmd = None
                try:
                    if pid:
                        p = psutil.Process(pid)
                        name = p.name()
                        username = p.username()
                        cmdline = p.cmdline()
                        if cmdline:
                            cmd = " ".join(cmdline)[:300]
                except Exception as e:
                    if logger:
                        logger.debug(f"psutil lookup failed for pid={pid}: {e}")

                # optional process substring filter
                hay = ((name or "") + " " + (cmd or "")).lower()
                if proc_filter and proc_filter not in hay:
                    continue

                rec = {
                    "proto": proto,
                    "status": status,
                    "pid": pid,
                    "process": name,
                    "user": username,
                    "laddr": (
                        {"ip": getattr(laddr, "ip", None), "port": lport}
                        if laddr
                        else None
                    ),
                    "raddr": (
                        {
                            "ip": getattr(raddr, "ip", None),
                            "port": getattr(raddr, "port", None),
                        }
                        if raddr
                        else None
                    ),
                    "cmd": cmd,
                }
                rows.append(rec)

                by_status[status] = by_status.get(status, 0) + 1
                if (proto == "tcp" and status == "LISTEN" and lport) or (
                    proto == "udp" and not raddr and lport
                ):
                    listening_ports.add(lport)
                if name:
                    by_proc_counts[name] = by_proc_counts.get(name, 0) + 1

            # Sort for readability: tcp first, then port, then process
            rows.sort(
                key=lambda x: (
                    x["proto"] != "tcp",
                    (x["laddr"] or {}).get("port") or 0,
                    x.get("process") or "",
                )
            )

            top_procs = sorted(
                [{"process": k, "count": v} for k, v in by_proc_counts.items()],
                key=lambda d: d["count"],
                reverse=True,
            )[:20]

            summary = {
                "total": len(rows),
                "by_status": by_status,
                "listening_ports": sorted(p for p in listening_ports if p is not None),
                "by_process_top": top_procs,
            }

            return jsonify(
                {
                    "success": True,
                    "timestamp": datetime.now().isoformat(),
                    "summary": summary,
                    "connections": rows,
                }
            )

        except Exception as e:
            if logger:
                logger.error(f"/api/network/ports failed: {e}")
                logger.debug(traceback.format_exc())
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/network/ss", methods=["GET"])
    def ss_raw():
        """Return raw `ss -lntp` output to compare with our parsed view."""
        try:
            args = ["ss", "-lntp"]
            r = subprocess.run(args, capture_output=True, text=True, timeout=6)
            return jsonify(
                {
                    "success": r.returncode == 0,
                    "command": " ".join(args),
                    "returncode": r.returncode,
                    "stdout": r.stdout,
                    "stderr": r.stderr,
                }
            )
        except Exception as e:
            if logger:
                logger.error(f"/api/network/ss failed: {e}")
            return jsonify({"success": False, "error": str(e)}), 500
