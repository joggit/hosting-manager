# src/api/services/next_port_service.py - Port management service
import subprocess
import psutil
import json
import re
import os
from datetime import datetime


class NextPortService:
    """Service for port management and Next.js process detection"""

    def __init__(self, deps):
        self.config = deps["config"]
        self.logger = deps["logger"]
        self.process_monitor = deps["process_monitor"]

    def get_nextjs_port_usage(self):
        """Get all ports currently in use by Next.js servers"""
        nextjs_ports = []

        try:
            # Method 1: Check PM2 processes for Next.js apps
            pm2_nextjs = self._get_pm2_nextjs_ports()
            nextjs_ports.extend(pm2_nextjs)

            # Method 2: Check system processes for Next.js patterns
            system_nextjs = self._get_system_nextjs_ports()
            nextjs_ports.extend(system_nextjs)

            # Method 3: Check our process monitor for Next.js apps
            monitor_nextjs = self._get_monitored_nextjs_ports()
            nextjs_ports.extend(monitor_nextjs)

            # Deduplicate by port number
            unique_ports = {}
            for port_info in nextjs_ports:
                port = port_info["port"]
                if port not in unique_ports:
                    unique_ports[port] = port_info
                else:
                    # Merge information if we have the same port from multiple sources
                    unique_ports[port] = self._merge_port_info(
                        unique_ports[port], port_info
                    )

            return list(unique_ports.values())

        except Exception as e:
            self.logger.error(f"Failed to get Next.js port usage: {e}")
            return []

    def _get_pm2_nextjs_ports(self):
        """Get Next.js ports from PM2 processes"""
        nextjs_ports = []

        try:
            if not self.process_monitor.pm2_available:
                return nextjs_ports

            result = subprocess.run(["pm2", "jlist"], capture_output=True, text=True)
            if result.returncode == 0:
                pm2_processes = json.loads(result.stdout)

                for proc in pm2_processes:
                    if self._is_nextjs_process(proc):
                        port_info = self._extract_pm2_port_info(proc)
                        if port_info:
                            nextjs_ports.append(port_info)

        except Exception as e:
            self.logger.error(f"Failed to get PM2 Next.js ports: {e}")

        return nextjs_ports

    def _get_system_nextjs_ports(self):
        """Get Next.js ports from system processes"""
        nextjs_ports = []

        try:
            # Get all processes with their command lines
            for proc in psutil.process_iter(["pid", "name", "cmdline", "connections"]):
                try:
                    proc_info = proc.info
                    if self._is_system_nextjs_process(proc_info):
                        port_info = self._extract_system_port_info(proc_info, proc)
                        if port_info:
                            nextjs_ports.append(port_info)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            self.logger.error(f"Failed to get system Next.js ports: {e}")

        return nextjs_ports

    def _get_monitored_nextjs_ports(self):
        """Get Next.js ports from our process monitor"""
        nextjs_ports = []

        try:
            processes = self.process_monitor.get_all_processes()

            for proc in processes:
                if self._is_monitored_nextjs_process(proc):
                    port_info = {
                        "port": proc.get("port"),
                        "name": proc.get("name"),
                        "status": proc.get("status"),
                        "pid": proc.get("pid"),
                        "process_manager": proc.get("process_manager"),
                        "source": "process_monitor",
                        "type": "nextjs",
                        "memory": proc.get("memory"),
                        "cpu": proc.get("cpu"),
                        "uptime": proc.get("uptime"),
                        "cwd": proc.get("cwd"),
                    }
                    nextjs_ports.append(port_info)

        except Exception as e:
            self.logger.error(f"Failed to get monitored Next.js ports: {e}")

        return nextjs_ports

    def _is_nextjs_process(self, pm2_proc):
        """Check if PM2 process is a Next.js application"""
        try:
            # Check script name
            script = pm2_proc.get("pm2_env", {}).get("pm_exec_path", "")
            if "next" in script.lower():
                return True

            # Check for Next.js in command args
            args = pm2_proc.get("pm2_env", {}).get("args", [])
            if any("next" in str(arg).lower() for arg in args):
                return True

            # Check working directory for Next.js indicators
            cwd = pm2_proc.get("pm2_env", {}).get("pm_cwd", "")
            if cwd and self._has_nextjs_indicators(cwd):
                return True

            return False

        except Exception:
            return False

    def _is_system_nextjs_process(self, proc_info):
        """Check if system process is a Next.js application"""
        try:
            cmdline = proc_info.get("cmdline", [])
            if not cmdline:
                return False

            cmdline_str = " ".join(cmdline).lower()

            # Look for Next.js indicators in command line
            nextjs_indicators = [
                "next start",
                "next dev",
                "next build",
                ".next",
                "node_modules/.bin/next",
                "npm run start",
                "npm start",
            ]

            for indicator in nextjs_indicators:
                if indicator in cmdline_str:
                    # Additional verification - check if it's actually Next.js
                    if "next" in cmdline_str or self._has_nextjs_port_pattern(
                        cmdline_str
                    ):
                        return True

            return False

        except Exception:
            return False

    def _is_monitored_nextjs_process(self, proc):
        """Check if monitored process is a Next.js application"""
        try:
            # Check process type
            if proc.get("type") == "nextjs":
                return True

            # Check working directory
            cwd = proc.get("cwd", "")
            if cwd and self._has_nextjs_indicators(cwd):
                return True

            # Check if port is in typical Next.js range and has Next.js characteristics
            port = proc.get("port")
            if port and 3000 <= port <= 4000:
                name = proc.get("name", "").lower()
                if any(
                    indicator in name
                    for indicator in ["next", "react", "frontend", "web"]
                ):
                    return True

            return False

        except Exception:
            return False

    def _has_nextjs_indicators(self, directory):
        """Check if directory contains Next.js indicators"""
        try:
            if not os.path.exists(directory):
                return False

            # Check for Next.js files
            nextjs_files = [
                "next.config.js",
                "next.config.mjs",
                "next.config.ts",
                ".next",
                "pages",
                "app",  # App router
            ]

            for file in nextjs_files:
                if os.path.exists(os.path.join(directory, file)):
                    return True

            # Check package.json for Next.js dependency
            package_json = os.path.join(directory, "package.json")
            if os.path.exists(package_json):
                try:
                    with open(package_json, "r") as f:
                        package_data = json.load(f)
                        deps = package_data.get("dependencies", {})
                        if "next" in deps:
                            return True
                except Exception:
                    pass

            return False

        except Exception:
            return False

    def _has_nextjs_port_pattern(self, cmdline):
        """Check if command line has typical Next.js port patterns"""
        # Look for port 3000 (default Next.js port) or PORT environment variable
        port_patterns = [
            r"port[=\s]+3000",
            r"PORT[=\s]+\d{4}",
            r"--port[=\s]+\d{4}",
            r"-p[=\s]+\d{4}",
        ]

        for pattern in port_patterns:
            if re.search(pattern, cmdline, re.IGNORECASE):
                return True

        return False

    def _extract_pm2_port_info(self, pm2_proc):
        """Extract port information from PM2 process"""
        try:
            env = pm2_proc.get("pm2_env", {})

            # Get port from environment
            port = env.get("env", {}).get("PORT")
            if not port:
                port = env.get("PORT")

            # Try to extract from command line args
            if not port:
                args = env.get("args", [])
                port = self._extract_port_from_args(args)

            if port:
                return {
                    "port": int(port),
                    "name": pm2_proc.get("name"),
                    "status": env.get("status"),
                    "pid": pm2_proc.get("pid"),
                    "pm2_id": pm2_proc.get("pm_id"),
                    "source": "pm2",
                    "type": "nextjs",
                    "cwd": env.get("pm_cwd"),
                    "script": env.get("pm_exec_path"),
                    "uptime": env.get("pm_uptime"),
                    "memory": pm2_proc.get("monit", {}).get("memory", 0),
                    "cpu": pm2_proc.get("monit", {}).get("cpu", 0),
                }

        except Exception as e:
            self.logger.error(f"Failed to extract PM2 port info: {e}")

        return None

    def _extract_system_port_info(self, proc_info, proc):
        """Extract port information from system process"""
        try:
            # Get listening connections for this process
            connections = []
            try:
                connections = proc.connections(kind="inet")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Find listening ports
            listening_ports = []
            for conn in connections:
                if conn.status == "LISTEN":
                    listening_ports.append(conn.laddr.port)

            # Try to identify the main Next.js port
            main_port = None
            if listening_ports:
                # Prefer ports in Next.js range (3000-4000)
                nextjs_ports = [p for p in listening_ports if 3000 <= p <= 4000]
                if nextjs_ports:
                    main_port = min(nextjs_ports)  # Take the lowest port in range
                else:
                    main_port = min(listening_ports)  # Take the lowest port overall

            if main_port:
                return {
                    "port": main_port,
                    "name": proc_info.get("name"),
                    "status": "running",
                    "pid": proc_info.get("pid"),
                    "source": "system",
                    "type": "nextjs",
                    "all_ports": listening_ports,
                    "cmdline": " ".join(proc_info.get("cmdline", [])),
                }

        except Exception as e:
            self.logger.error(f"Failed to extract system port info: {e}")

        return None

    def _extract_port_from_args(self, args):
        """Extract port number from command line arguments"""
        try:
            args_str = " ".join(str(arg) for arg in args)

            # Common port patterns
            patterns = [
                r"--port[=\s]+(\d+)",
                r"-p[=\s]+(\d+)",
                r"PORT[=\s]+(\d+)",
                r"port[=\s]+(\d+)",
            ]

            for pattern in patterns:
                match = re.search(pattern, args_str, re.IGNORECASE)
                if match:
                    return int(match.group(1))

        except Exception:
            pass

        return None

    def _merge_port_info(self, info1, info2):
        """Merge information from multiple sources for the same port"""
        merged = info1.copy()

        # Prefer PM2 info over system info
        if info2.get("source") == "pm2" and info1.get("source") != "pm2":
            merged.update(info2)
        elif info1.get("source") != "pm2" and info2.get("source") != "pm2":
            # Merge non-PM2 sources
            for key, value in info2.items():
                if key not in merged or not merged[key]:
                    merged[key] = value

        # Always merge sources list
        sources = set()
        if isinstance(merged.get("source"), list):
            sources.update(merged["source"])
        else:
            sources.add(merged.get("source"))

        if isinstance(info2.get("source"), list):
            sources.update(info2["source"])
        else:
            sources.add(info2.get("source"))

        merged["sources"] = list(sources)

        return merged

    def get_nextjs_port_summary(self, nextjs_ports):
        """Get summary statistics for Next.js port usage"""
        try:
            if not nextjs_ports:
                return {
                    "total_ports": 0,
                    "running_ports": 0,
                    "stopped_ports": 0,
                    "port_range": None,
                    "sources": [],
                }

            running_count = len(
                [p for p in nextjs_ports if p.get("status") in ["running", "online"]]
            )
            stopped_count = len(nextjs_ports) - running_count

            ports = [p["port"] for p in nextjs_ports if p.get("port")]
            port_range = f"{min(ports)}-{max(ports)}" if ports else None

            sources = set()
            for port_info in nextjs_ports:
                if isinstance(port_info.get("sources"), list):
                    sources.update(port_info["sources"])
                else:
                    sources.add(port_info.get("source"))

            return {
                "total_ports": len(nextjs_ports),
                "running_ports": running_count,
                "stopped_ports": stopped_count,
                "port_range": port_range,
                "sources": list(sources),
                "ports_by_status": self._group_ports_by_status(nextjs_ports),
            }

        except Exception as e:
            self.logger.error(f"Failed to generate port summary: {e}")
            return {"error": str(e)}

    def _group_ports_by_status(self, nextjs_ports):
        """Group ports by their status"""
        groups = {}
        for port_info in nextjs_ports:
            status = port_info.get("status", "unknown")
            if status not in groups:
                groups[status] = []
            groups[status].append(port_info["port"])
        return groups

    def get_all_listening_ports(self):
        """Get all listening ports on the system"""
        listening_ports = []

        try:
            # Use netstat or ss to get listening ports
            try:
                result = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True)
                if result.returncode == 0:
                    listening_ports = self._parse_ss_output(result.stdout)
                else:
                    raise subprocess.CalledProcessError(result.returncode, "ss")
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Fallback to netstat
                result = subprocess.run(
                    ["netstat", "-tlnp"], capture_output=True, text=True
                )
                if result.returncode == 0:
                    listening_ports = self._parse_netstat_output(result.stdout)

        except Exception as e:
            self.logger.error(f"Failed to get listening ports: {e}")

        return listening_ports

    def _parse_ss_output(self, output):
        """Parse ss command output"""
        ports = []
        lines = output.strip().split("\n")[1:]  # Skip header

        for line in lines:
            try:
                parts = line.split()
                if len(parts) >= 4:
                    local_addr = parts[3]
                    process_info = parts[-1] if len(parts) > 4 else ""

                    # Extract port from address (format: *:port or ip:port)
                    if ":" in local_addr:
                        port_str = local_addr.split(":")[-1]
                        try:
                            port = int(port_str)
                            ports.append(
                                {
                                    "port": port,
                                    "protocol": parts[0].lower(),
                                    "address": local_addr,
                                    "process": process_info,
                                    "source": "ss",
                                }
                            )
                        except ValueError:
                            continue

            except Exception:
                continue

        return ports

    def _parse_netstat_output(self, output):
        """Parse netstat command output"""
        ports = []
        lines = output.strip().split("\n")[2:]  # Skip headers

        for line in lines:
            try:
                parts = line.split()
                if len(parts) >= 4 and "LISTEN" in line:
                    local_addr = parts[3]
                    process_info = parts[-1] if len(parts) > 6 else ""

                    # Extract port from address
                    if ":" in local_addr:
                        port_str = local_addr.split(":")[-1]
                        try:
                            port = int(port_str)
                            ports.append(
                                {
                                    "port": port,
                                    "protocol": parts[0].lower(),
                                    "address": local_addr,
                                    "process": process_info,
                                    "source": "netstat",
                                }
                            )
                        except ValueError:
                            continue

            except Exception:
                continue

        return ports

    def check_port_range(self, start_port, end_port):
        """Check port availability in a specific range"""
        try:
            listening_ports = self.get_all_listening_ports()
            used_ports = {p["port"] for p in listening_ports}

            range_analysis = {
                "start_port": start_port,
                "end_port": end_port,
                "total_ports": end_port - start_port,
                "used_ports": [],
                "available_ports": [],
                "used_count": 0,
                "available_count": 0,
            }

            for port in range(start_port, end_port):
                if port in used_ports:
                    port_info = next(
                        (p for p in listening_ports if p["port"] == port), None
                    )
                    range_analysis["used_ports"].append(
                        {
                            "port": port,
                            "process": (
                                port_info.get("process", "") if port_info else ""
                            ),
                            "protocol": (
                                port_info.get("protocol", "") if port_info else ""
                            ),
                        }
                    )
                else:
                    range_analysis["available_ports"].append(port)

            range_analysis["used_count"] = len(range_analysis["used_ports"])
            range_analysis["available_count"] = len(range_analysis["available_ports"])

            return range_analysis

        except Exception as e:
            self.logger.error(f"Failed to check port range: {e}")
            return {"error": str(e)}

    def suggest_available_ports(self, count, preferred_range, avoid_ports):
        """Suggest available ports for new applications"""
        try:
            # Parse preferred range
            if "-" in preferred_range:
                start, end = map(int, preferred_range.split("-"))
            else:
                start, end = 3000, 4000

            # Get used ports
            listening_ports = self.get_all_listening_ports()
            used_ports = {p["port"] for p in listening_ports}
            used_ports.update(avoid_ports)

            # Find available ports in preferred range
            suggestions = []
            for port in range(start, end):
                if port not in used_ports:
                    suggestions.append(
                        {
                            "port": port,
                            "status": "available",
                            "recommendation_score": self._calculate_port_score(
                                port, start, end
                            ),
                        }
                    )

                    if len(suggestions) >= count:
                        break

            # Sort by recommendation score
            suggestions.sort(key=lambda x: x["recommendation_score"], reverse=True)

            return suggestions[:count]

        except Exception as e:
            self.logger.error(f"Failed to suggest ports: {e}")
            return []

    def _calculate_port_score(self, port, range_start, range_end):
        """Calculate recommendation score for a port"""
        score = 100

        # Prefer ports closer to the start of the range
        distance_penalty = (port - range_start) / (range_end - range_start) * 20
        score -= distance_penalty

        # Prefer common Next.js ports
        if port == 3000:  # Default Next.js port
            score += 50
        elif port in [3001, 3002, 3003]:  # Common alternatives
            score += 30
        elif 3000 <= port <= 3010:  # Next.js range
            score += 20

        # Avoid system ports
        if port < 1024:
            score -= 100
        elif port < 3000:
            score -= 50

        return max(0, score)

    def detect_port_conflicts(self):
        """Detect potential port conflicts and issues"""
        conflicts = []

        try:
            nextjs_ports = self.get_nextjs_port_usage()
            all_ports = self.get_all_listening_ports()

            # Check for multiple Next.js apps on same port
            port_counts = {}
            for app in nextjs_ports:
                port = app["port"]
                if port not in port_counts:
                    port_counts[port] = []
                port_counts[port].append(app)

            for port, apps in port_counts.items():
                if len(apps) > 1:
                    conflicts.append(
                        {
                            "type": "multiple_nextjs_same_port",
                            "port": port,
                            "severity": "high",
                            "description": f"Multiple Next.js apps trying to use port {port}",
                            "apps": [app["name"] for app in apps],
                            "recommendation": f"Assign different ports to these applications",
                        }
                    )

            # Check for Next.js apps on system ports
            for app in nextjs_ports:
                port = app["port"]
                if port < 1024:
                    conflicts.append(
                        {
                            "type": "system_port_usage",
                            "port": port,
                            "severity": "medium",
                            "description": f"Next.js app '{app['name']}' is using system port {port}",
                            "app": app["name"],
                            "recommendation": f"Move to a higher port number (3000+)",
                        }
                    )

            # Check for stopped Next.js apps blocking ports
            for app in nextjs_ports:
                if app.get("status") not in ["running", "online"]:
                    conflicts.append(
                        {
                            "type": "stopped_app_blocking_port",
                            "port": app["port"],
                            "severity": "low",
                            "description": f"Stopped app '{app['name']}' may be blocking port {app['port']}",
                            "app": app["name"],
                            "recommendation": "Remove or restart the application",
                        }
                    )

        except Exception as e:
            self.logger.error(f"Failed to detect port conflicts: {e}")

        return conflicts

    def get_conflict_recommendations(self, conflicts):
        """Get recommendations for resolving port conflicts"""
        recommendations = []

        high_severity = [c for c in conflicts if c.get("severity") == "high"]
        medium_severity = [c for c in conflicts if c.get("severity") == "medium"]

        if high_severity:
            recommendations.append(
                {
                    "priority": "urgent",
                    "message": f"Resolve {len(high_severity)} high-severity port conflicts immediately",
                    "actions": [
                        "Stop conflicting applications",
                        "Reassign ports",
                        "Update configurations",
                    ],
                }
            )

        if medium_severity:
            recommendations.append(
                {
                    "priority": "important",
                    "message": f"Address {len(medium_severity)} medium-severity port issues",
                    "actions": [
                        "Move apps to non-system ports",
                        "Update port configurations",
                    ],
                }
            )

        if len(conflicts) > 5:
            recommendations.append(
                {
                    "priority": "maintenance",
                    "message": "Consider implementing automated port management",
                    "actions": [
                        "Use dynamic port assignment",
                        "Implement port pools",
                        "Add health checks",
                    ],
                }
            )

        return recommendations

    def analyze_port_ranges(self, listening_ports):
        """Analyze port usage by ranges"""
        ranges = {
            "system_ports": {"range": "1-1023", "count": 0, "ports": []},
            "registered_ports": {"range": "1024-49151", "count": 0, "ports": []},
            "dynamic_ports": {"range": "49152-65535", "count": 0, "ports": []},
            "nextjs_common": {"range": "3000-3999", "count": 0, "ports": []},
            "development_common": {"range": "8000-8999", "count": 0, "ports": []},
        }

        for port_info in listening_ports:
            port = port_info["port"]

            if 1 <= port <= 1023:
                ranges["system_ports"]["count"] += 1
                ranges["system_ports"]["ports"].append(port)
            elif 1024 <= port <= 49151:
                ranges["registered_ports"]["count"] += 1
                ranges["registered_ports"]["ports"].append(port)
            elif 49152 <= port <= 65535:
                ranges["dynamic_ports"]["count"] += 1
                ranges["dynamic_ports"]["ports"].append(port)

            if 3000 <= port <= 3999:
                ranges["nextjs_common"]["count"] += 1
                ranges["nextjs_common"]["ports"].append(port)
            elif 8000 <= port <= 8999:
                ranges["development_common"]["count"] += 1
                ranges["development_common"]["ports"].append(port)

        return ranges


# Update src/api/routes/__init__.py to include the new routes
# Add this line to the imports:
# from .port_management import register_port_management_routes

# Add this line to register_all_routes function:
# register_port_management_routes(app, dependencies)
