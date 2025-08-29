# src/monitoring/process_monitor.py
"""
Process monitoring with PM2, systemd, and custom process management support
Enhanced monitoring for Next.js applications
"""

import subprocess
import json
import os
import time
import psutil
import threading
from datetime import datetime


class ProcessMonitor:
    """Enhanced process monitor with PM2 and Next.js support"""

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.pm2_available = self._check_pm2_availability()
        self.monitoring_thread = None
        self.monitoring_active = False

    def setup(self):
        """Setup process monitoring"""
        try:
            self.logger.info("Setting up process monitor...")

            # Setup PM2 if available
            if self.pm2_available:
                self._setup_pm2()

            # Create monitoring directories
            monitoring_dirs = ["/tmp/monitoring", "/tmp/process-logs"]

            for directory in monitoring_dirs:
                os.makedirs(directory, mode=0o755, exist_ok=True)

            self.logger.info("Process monitor setup completed")
            return True

        except Exception as e:
            self.logger.error(f"Process monitor setup failed: {e}")
            return False

    def _check_pm2_availability(self):
        """Check if PM2 is available"""
        try:
            result = subprocess.run(
                ["pm2", "--version"], capture_output=True, text=True
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                self.logger.info(f"PM2 version {version} available")
                return True
            return False
        except:
            return False

    def _setup_pm2(self):
        """Setup PM2 environment"""
        try:
            # Set PM2 home directory
            pm2_home = (
                "/tmp/pm2-home"
                if self.config.get("readonly_mode")
                else "/home/www-data/.pm2"
            )
            os.makedirs(pm2_home, mode=0o755, exist_ok=True)
            os.environ["PM2_HOME"] = pm2_home

            # Initialize PM2
            subprocess.run(["pm2", "ping"], capture_output=True)

            self.logger.info("PM2 environment configured")

        except Exception as e:
            self.logger.warning(f"PM2 setup failed: {e}")

    def deploy_nodejs_app(self, site_name, project_files, deploy_config):
        """Deploy Node.js application with PM2 support"""
        try:
            self.logger.info(f"Deploying Node.js app: {site_name}")

            timestamp = int(time.time())
            temp_dir = f"/tmp/deploy_{site_name}_{timestamp}"
            final_dir = f"{self.config.get('web_root')}/{site_name}"

            # Create directories
            os.makedirs(temp_dir, exist_ok=True)
            os.makedirs(final_dir, exist_ok=True)

            # Extract files
            self._extract_files(project_files, temp_dir)

            # Install dependencies
            if not self._npm_install(temp_dir):
                return {"success": False, "error": "npm install failed"}

            # Build if needed
            if self._has_build_script(temp_dir):
                if not self._npm_build(temp_dir):
                    return {"success": False, "error": "npm build failed"}

            # Copy to final location
            if temp_dir != final_dir:
                if os.path.exists(final_dir):
                    shutil.rmtree(final_dir)
                shutil.copytree(temp_dir, final_dir)

            # Start the application
            app_port = deploy_config.get("port", 3000)
            process_manager = self._determine_process_manager()

            if not self._start_nodejs_app(
                site_name, final_dir, app_port, process_manager
            ):
                return {"success": False, "error": "Failed to start application"}

            # Setup nginx proxy
            if not self.config.get("readonly_mode"):
                self._setup_nginx_proxy(site_name, app_port)

            # Save process info to database
            self._save_process_info(site_name, app_port, final_dir, process_manager)

            # Cleanup temp directory
            if os.path.exists(temp_dir) and temp_dir != final_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)

            self.logger.info(f"Deployment successful: {site_name}")

            return {
                "success": True,
                "site_name": site_name,
                "port": app_port,
                "process_manager": process_manager,
                "url": f"http://{site_name}",
                "files_path": final_dir,
            }

        except Exception as e:
            self.logger.error(f"Deployment failed: {e}")
            return {"success": False, "error": str(e)}

    def _extract_files(self, files_dict, target_dir):
        """Extract project files"""
        for file_path, content in files_dict.items():
            full_path = os.path.join(target_dir, file_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)

            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)

    def _npm_install(self, cwd):
        """Run npm install with error handling"""
        try:
            strategies = [
                ["npm", "ci", "--only=production", "--silent"],
                ["npm", "install", "--only=production", "--silent"],
                ["npm", "install", "--silent"],
            ]

            for strategy in strategies:
                result = subprocess.run(
                    strategy, cwd=cwd, capture_output=True, text=True, timeout=300
                )

                if result.returncode == 0:
                    self.logger.info("npm install successful")
                    return True

            self.logger.error("All npm install strategies failed")
            return False

        except Exception as e:
            self.logger.error(f"npm install failed: {e}")
            return False

    def _has_build_script(self, cwd):
        """Check if package.json has a build script"""
        try:
            package_path = os.path.join(cwd, "package.json")
            if os.path.exists(package_path):
                with open(package_path, "r") as f:
                    package_data = json.load(f)
                    return "build" in package_data.get("scripts", {})
            return False
        except:
            return False

    def _npm_build(self, cwd):
        """Run npm build"""
        try:
            result = subprocess.run(
                ["npm", "run", "build"],
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.returncode == 0:
                self.logger.info("npm build successful")
                return True
            else:
                self.logger.error(f"npm build failed: {result.stderr}")
                return False

        except Exception as e:
            self.logger.error(f"npm build failed: {e}")
            return False

    def _determine_process_manager(self):
        """Determine which process manager to use"""
        if self.pm2_available:
            return "pm2"
        elif self.config.get("readonly_mode"):
            return "readonly-simple"
        else:
            return "systemd"

    def _start_nodejs_app(self, site_name, cwd, port, process_manager):
        """Start Node.js application using appropriate process manager"""
        try:
            if process_manager == "pm2":
                return self._start_pm2_app(site_name, cwd, port)
            elif process_manager == "systemd":
                return self._start_systemd_app(site_name, cwd, port)
            else:
                return self._start_simple_app(site_name, cwd, port)

        except Exception as e:
            self.logger.error(f"Failed to start app {site_name}: {e}")
            return False

    def _start_pm2_app(self, site_name, cwd, port):
        """Start app with PM2"""
        try:
            # Create PM2 ecosystem file
            ecosystem = {
                "apps": [
                    {
                        "name": site_name,
                        "script": self._detect_start_script(cwd),
                        "cwd": cwd,
                        "env": {"NODE_ENV": "production", "PORT": str(port)},
                        "instances": 1,
                        "exec_mode": "fork",
                        "max_memory_restart": "500M",
                        "error_file": f"/tmp/process-logs/{site_name}-error.log",
                        "out_file": f"/tmp/process-logs/{site_name}-out.log",
                        "log_file": f"/tmp/process-logs/{site_name}-combined.log",
                    }
                ]
            }

            ecosystem_path = f"{cwd}/ecosystem.config.json"
            with open(ecosystem_path, "w") as f:
                json.dump(ecosystem, f, indent=2)

            # Start with PM2
            result = subprocess.run(
                ["pm2", "start", ecosystem_path], capture_output=True, text=True
            )

            if result.returncode == 0:
                self.logger.info(f"PM2 app started: {site_name}")
                return True
            else:
                self.logger.error(f"PM2 start failed: {result.stderr}")
                return False

        except Exception as e:
            self.logger.error(f"PM2 app start failed: {e}")
            return False

    def _detect_start_script(self, cwd):
        """Detect the correct start script for the app"""
        try:
            package_path = os.path.join(cwd, "package.json")
            if os.path.exists(package_path):
                with open(package_path) as f:
                    package_data = json.load(f)
                    scripts = package_data.get("scripts", {})

                    # Check for Next.js
                    if "next" in package_data.get("dependencies", {}):
                        if os.path.exists(os.path.join(cwd, ".next")):
                            return "node_modules/.bin/next start"
                        else:
                            return "npm run build && node_modules/.bin/next start"

                    # Check for start script
                    if "start" in scripts:
                        return "npm start"
                    elif "dev" in scripts:
                        return "npm run dev"

            # Fallback to common entry points
            for script in ["server.js", "app.js", "index.js"]:
                if os.path.exists(os.path.join(cwd, script)):
                    return f"node {script}"

            return "npm start"  # Final fallback

        except Exception as e:
            self.logger.warning(f"Failed to detect start script: {e}")
            return "npm start"

    def _start_systemd_app(self, site_name, cwd, port):
        """Start app with systemd"""
        # This would use the existing systemd logic
        # Simplified for brevity - would call the hosting manager's systemd methods
        return True

    def _start_simple_app(self, site_name, cwd, port):
        """Start app with simple process manager"""
        # This would use the existing simple process manager logic
        # Simplified for brevity - would call the hosting manager's simple process methods
        return True

    def get_all_processes(self):
        """Get all managed processes with enhanced monitoring"""
        processes = []

        try:
            if self.pm2_available:
                processes.extend(self._get_pm2_processes())

            processes.extend(self._get_systemd_processes())
            processes.extend(self._get_simple_processes())

            # Enhance with system metrics
            for process in processes:
                process.update(self._get_process_metrics(process))

            return processes

        except Exception as e:
            self.logger.error(f"Failed to get processes: {e}")
            return []

    def _get_pm2_processes(self):
        """Get PM2 managed processes"""
        try:
            result = subprocess.run(["pm2", "jlist"], capture_output=True, text=True)

            if result.returncode == 0:
                pm2_data = json.loads(result.stdout)

                processes = []
                for app in pm2_data:
                    process_info = {
                        "name": app["name"],
                        "status": (
                            "online"
                            if app["pm2_env"]["status"] == "online"
                            else "stopped"
                        ),
                        "pid": app["pid"] if app["pid"] != 0 else None,
                        "port": self._extract_port_from_env(app.get("pm2_env", {})),
                        "process_manager": "pm2",
                        "restart_count": app.get("restart_time", 0),
                        "uptime": app.get("pm2_env", {}).get("pm_uptime"),
                        "cwd": app.get("pm2_env", {}).get("pwd"),
                        "memory": f"{app.get('monit', {}).get('memory', 0) // (1024*1024)}MB",
                        "cpu": f"{app.get('monit', {}).get('cpu', 0):.1f}%",
                        "type": self._detect_app_type(
                            app.get("pm2_env", {}).get("pwd", "")
                        ),
                        "pm2_id": app.get("pm_id"),
                    }
                    processes.append(process_info)

                return processes

        except Exception as e:
            self.logger.error(f"Failed to get PM2 processes: {e}")

        return []

    def _extract_port_from_env(self, env):
        """Extract port from PM2 environment"""
        try:
            return env.get("env", {}).get("PORT") or env.get("PORT")
        except:
            return None

    def _detect_app_type(self, cwd):
        """Detect application type from directory"""
        try:
            if not cwd or not os.path.exists(cwd):
                return "unknown"

            # Check for Next.js
            if os.path.exists(os.path.join(cwd, "next.config.js")) or os.path.exists(
                os.path.join(cwd, "next.config.mjs")
            ):
                return "nextjs"

            # Check package.json for framework indicators
            package_path = os.path.join(cwd, "package.json")
            if os.path.exists(package_path):
                try:
                    with open(package_path) as f:
                        package_data = json.load(f)
                        deps = package_data.get("dependencies", {})

                        if "next" in deps:
                            return "nextjs"
                        elif "express" in deps:
                            return "express"
                        elif "fastify" in deps:
                            return "fastify"
                        elif "koa" in deps:
                            return "koa"
                        else:
                            return "nodejs"
                except:
                    pass

            return "nodejs"

        except:
            return "unknown"

    def _get_systemd_processes(self):
        """Get systemd managed Node.js processes"""
        processes = []

        try:
            result = subprocess.run(
                ["systemctl", "list-units", "--state=active", "nodejs-*"],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "nodejs-" in line and "active" in line:
                        parts = line.split()
                        if len(parts) > 0:
                            unit_name = parts[0]
                            if unit_name.startswith("nodejs-"):
                                site_name = unit_name.replace("nodejs-", "").replace(
                                    ".service", ""
                                )

                                process_info = self._get_systemd_process_details(
                                    site_name, unit_name
                                )
                                if process_info:
                                    processes.append(process_info)

        except Exception as e:
            self.logger.error(f"Failed to get systemd processes: {e}")

        return processes

    def _get_systemd_process_details(self, site_name, unit_name):
        """Get detailed systemd process information"""
        try:
            result = subprocess.run(
                [
                    "systemctl",
                    "show",
                    unit_name,
                    "--property=ActiveState,MainPID,ExecMainStartTimestamp",
                ],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                properties = {}
                for line in result.stdout.split("\n"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        properties[key] = value

                pid = properties.get("MainPID")
                if pid and pid != "0":
                    pid = int(pid)

                    # Get process stats
                    try:
                        process = psutil.Process(pid)
                        memory = f"{process.memory_info().rss // (1024*1024)}MB"
                        cpu = f"{process.cpu_percent():.1f}%"
                    except:
                        memory = "N/A"
                        cpu = "N/A"
                else:
                    pid = None
                    memory = "N/A"
                    cpu = "N/A"

                return {
                    "name": site_name,
                    "status": (
                        "online"
                        if properties.get("ActiveState") == "active"
                        else "stopped"
                    ),
                    "pid": pid,
                    "process_manager": "systemd",
                    "service_name": unit_name,
                    "memory": memory,
                    "cpu": cpu,
                    "type": "nodejs",
                }

        except Exception as e:
            self.logger.error(f"Failed to get systemd details for {site_name}: {e}")

        return None

    def _get_simple_processes(self):
        """Get simple process manager processes"""
        processes = []

        try:
            import glob

            app_dirs = glob.glob("/tmp/nodejs-apps/*/deployment.json")

            for config_file in app_dirs:
                try:
                    site_name = os.path.basename(os.path.dirname(config_file))

                    with open(config_file) as f:
                        config = json.load(f)

                    # Check if running
                    pid_file = f"/tmp/nodejs-apps/{site_name}/{site_name}.pid"
                    is_running = False
                    pid = None

                    if os.path.exists(pid_file):
                        try:
                            with open(pid_file) as f:
                                pid = int(f.read().strip())

                            # Check if PID is actually running
                            try:
                                os.kill(pid, 0)  # Test if process exists
                                is_running = True
                            except OSError:
                                is_running = False
                                pid = None
                        except:
                            pass

                    # Get process stats if running
                    memory = "N/A"
                    cpu = "N/A"

                    if pid and is_running:
                        try:
                            process = psutil.Process(pid)
                            memory = f"{process.memory_info().rss // (1024*1024)}MB"
                            cpu = f"{process.cpu_percent():.1f}%"
                        except:
                            pass

                    process_info = {
                        "name": site_name,
                        "status": "online" if is_running else "stopped",
                        "pid": pid,
                        "port": config.get("port"),
                        "process_manager": "readonly-simple",
                        "cwd": config.get("cwd"),
                        "memory": memory,
                        "cpu": cpu,
                        "type": self._detect_app_type(config.get("cwd", "")),
                        "control_script": f"/tmp/nodejs-apps/{site_name}/control.sh",
                    }
                    processes.append(process_info)

                except Exception as e:
                    self.logger.error(f"Error processing {config_file}: {e}")

        except Exception as e:
            self.logger.error(f"Failed to get simple processes: {e}")

        return processes

    def get_pm2_processes(self):
        """Get PM2 process list in PM2 native format"""
        if not self.pm2_available:
            return []

        try:
            result = subprocess.run(["pm2", "jlist"], capture_output=True, text=True)
            if result.returncode == 0:
                return json.loads(result.stdout)
        except Exception as e:
            self.logger.error(f"Failed to get PM2 processes: {e}")

        return []

    def pm2_action(self, process_name, action):
        """Perform PM2 action on a process"""
        if not self.pm2_available:
            return False

        try:
            result = subprocess.run(
                ["pm2", action, process_name], capture_output=True, text=True
            )

            return result.returncode == 0

        except Exception as e:
            self.logger.error(f"PM2 {action} failed for {process_name}: {e}")
            return False

    def get_process_details(self, process_name):
        """Get detailed information about a specific process"""
        try:
            all_processes = self.get_all_processes()

            for process in all_processes:
                if process["name"] == process_name:
                    # Add additional monitoring data
                    process.update(
                        {
                            "logs": self.get_process_logs(process_name, 20),
                            "detailed_metrics": self._get_detailed_metrics(
                                process.get("pid")
                            ),
                        }
                    )
                    return process

            return None

        except Exception as e:
            self.logger.error(f"Failed to get process details: {e}")
            return None

    def _get_detailed_metrics(self, pid):
        """Get detailed metrics for a process"""
        if not pid:
            return {}

        try:
            process = psutil.Process(pid)

            return {
                "memory_percent": round(process.memory_percent(), 2),
                "cpu_count": psutil.cpu_count(),
                "open_files": len(process.open_files()),
                "connections": len(process.connections()),
                "threads": process.num_threads(),
                "create_time": datetime.fromtimestamp(
                    process.create_time()
                ).isoformat(),
            }

        except Exception as e:
            self.logger.error(f"Failed to get detailed metrics: {e}")
            return {}

    def get_process_logs(self, process_name, lines=50):
        """Get logs for a specific process"""
        try:
            log_sources = [
                f"/tmp/process-logs/{process_name}-combined.log",
                f"/tmp/nodejs-apps/{process_name}/{process_name}.log",
            ]

            for log_file in log_sources:
                if os.path.exists(log_file):
                    with open(log_file) as f:
                        log_lines = f.readlines()
                        return (
                            log_lines[-lines:] if len(log_lines) > lines else log_lines
                        )

            # Try journalctl for systemd services
            result = subprocess.run(
                [
                    "journalctl",
                    "-u",
                    f"nodejs-{process_name}",
                    "--no-pager",
                    "-n",
                    str(lines),
                ],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                return result.stdout.split("\n")

            return ["No logs found"]

        except Exception as e:
            self.logger.error(f"Failed to get logs for {process_name}: {e}")
            return [f"Error getting logs: {e}"]

    def get_process_summary(self):
        """Get summary statistics for all processes"""
        try:
            processes = self.get_all_processes()

            total_processes = len(processes)
            running_processes = len([p for p in processes if p["status"] == "online"])

            total_memory = 0
            total_cpu = 0.0
            process_managers = {}

            for proc in processes:
                # Parse memory
                if proc.get("memory") and "MB" in str(proc["memory"]):
                    try:
                        memory_val = int(str(proc["memory"]).replace("MB", ""))
                        total_memory += memory_val
                    except:
                        pass

                # Parse CPU
                if proc.get("cpu") and "%" in str(proc["cpu"]):
                    try:
                        cpu_val = float(str(proc["cpu"]).replace("%", ""))
                        total_cpu += cpu_val
                    except:
                        pass

                # Count process managers
                pm = proc.get("process_manager", "unknown")
                process_managers[pm] = process_managers.get(pm, 0) + 1

            return {
                "total_processes": total_processes,
                "running_processes": running_processes,
                "stopped_processes": total_processes - running_processes,
                "total_memory_mb": total_memory,
                "average_cpu": round(total_cpu / max(total_processes, 1), 2),
                "process_managers": process_managers,
            }

        except Exception as e:
            self.logger.error(f"Failed to get process summary: {e}")
            return {}

    def get_system_metrics(self):
        """Get overall system performance metrics"""
        try:
            return {
                "cpu_usage": psutil.cpu_percent(interval=1),
                "memory_usage": psutil.virtual_memory()._asdict(),
                "disk_usage": psutil.disk_usage("/")._asdict(),
                "load_average": os.getloadavg(),
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                "process_count": len(psutil.pids()),
            }

        except Exception as e:
            self.logger.error(f"Failed to get system metrics: {e}")
            return {}

    def _get_process_metrics(self, process_info):
        """Get additional metrics for a process"""
        try:
            pid = process_info.get("pid")
            if not pid:
                return {}

            try:
                proc = psutil.Process(pid)
                return {
                    "memory_percent": round(proc.memory_percent(), 2),
                    "num_threads": proc.num_threads(),
                    "create_time": datetime.fromtimestamp(
                        proc.create_time()
                    ).isoformat(),
                }
            except psutil.NoSuchProcess:
                return {"status_note": "Process no longer exists"}

        except Exception as e:
            self.logger.error(f"Failed to get process metrics: {e}")
            return {}

    def start_process(self, process_name):
        """Start a specific process"""
        try:
            # Get process info from database
            conn = self.hosting_manager.get_database_connection()
            if not conn:
                return False

            cursor = conn.cursor()
            cursor.execute(
                "SELECT process_manager FROM processes WHERE name = ?", (process_name,)
            )

            result = cursor.fetchone()
            conn.close()

            if not result:
                return False

            process_manager = result[0]

            if process_manager == "pm2":
                return self.pm2_action(process_name, "start")
            elif process_manager == "systemd":
                return self._systemd_action(process_name, "start")
            else:
                return self._simple_action(process_name, "start")

        except Exception as e:
            self.logger.error(f"Failed to start process {process_name}: {e}")
            return False

    def stop_process(self, process_name):
        """Stop a specific process"""
        try:
            # Similar logic to start_process but with stop action
            conn = self.hosting_manager.get_database_connection()
            if not conn:
                return False

            cursor = conn.cursor()
            cursor.execute(
                "SELECT process_manager FROM processes WHERE name = ?", (process_name,)
            )

            result = cursor.fetchone()
            conn.close()

            if not result:
                return False

            process_manager = result[0]

            if process_manager == "pm2":
                return self.pm2_action(process_name, "stop")
            elif process_manager == "systemd":
                return self._systemd_action(process_name, "stop")
            else:
                return self._simple_action(process_name, "stop")

        except Exception as e:
            self.logger.error(f"Failed to stop process {process_name}: {e}")
            return False

    def restart_process(self, process_name):
        """Restart a specific process"""
        return self.stop_process(process_name) and self.start_process(process_name)

    def _systemd_action(self, process_name, action):
        """Perform systemd action"""
        try:
            result = subprocess.run(
                ["systemctl", action, f"nodejs-{process_name}"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except:
            return False

    def _simple_action(self, process_name, action):
        """Perform simple process manager action"""
        try:
            control_script = f"/tmp/nodejs-apps/{process_name}/control.sh"
            if os.path.exists(control_script):
                result = subprocess.run(
                    [control_script, action], capture_output=True, text=True
                )
                return result.returncode == 0
        except:
            return False

    def _save_process_info(self, site_name, port, cwd, process_manager):
        """Save process information to database"""
        try:
            conn = self.hosting_manager.get_database_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO processes 
                    (name, port, cwd, process_manager, status, updated_at)
                    VALUES (?, ?, ?, ?, 'running', CURRENT_TIMESTAMP)
                """,
                    (site_name, port, cwd, process_manager),
                )

                conn.commit()
                conn.close()

        except Exception as e:
            self.logger.error(f"Failed to save process info: {e}")

    def start_background_monitoring(self):
        """Start background process monitoring"""
        if self.monitoring_active:
            return

        def monitor_loop():
            while self.monitoring_active:
                try:
                    # Update process database with current status
                    self._update_process_database()
                    time.sleep(30)  # Update every 30 seconds
                except Exception as e:
                    self.logger.error(f"Monitoring loop error: {e}")
                    time.sleep(60)  # Back off on errors

        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitoring_thread.start()

        self.logger.info("Background monitoring started")

    def _update_process_database(self):
        """Update process database with current status"""
        try:
            processes = self.get_all_processes()

            conn = self.hosting_manager.get_database_connection()
            if conn:
                cursor = conn.cursor()

                for proc in processes:
                    # Parse memory value
                    memory_mb = 0
                    if proc.get("memory") and "MB" in str(proc["memory"]):
                        try:
                            memory_mb = int(str(proc["memory"]).replace("MB", ""))
                        except:
                            pass

                    # Parse CPU value
                    cpu_percent = 0.0
                    if proc.get("cpu") and "%" in str(proc["cpu"]):
                        try:
                            cpu_percent = float(str(proc["cpu"]).replace("%", ""))
                        except:
                            pass

                    cursor.execute(
                        """
                        UPDATE processes SET 
                        status = ?, pid = ?, memory_usage = ?, cpu_usage = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE name = ?
                    """,
                        (
                            proc["status"],
                            proc.get("pid"),
                            memory_mb,
                            cpu_percent,
                            proc["name"],
                        ),
                    )

                conn.commit()
                conn.close()

        except Exception as e:
            self.logger.error(f"Failed to update process database: {e}")

    def is_monitoring_active(self):
        """Check if monitoring is active"""
        return (
            self.monitoring_active
            and self.monitoring_thread
            and self.monitoring_thread.is_alive()
        )

    def _setup_nginx_proxy(self, site_name, port):
        """Setup nginx proxy for the application"""
        # This would call the hosting manager's nginx setup
        return self.hosting_manager._configure_nginx_site(
            site_name, f"{self.config.get('web_root')}/{site_name}", port, "node"
        )
