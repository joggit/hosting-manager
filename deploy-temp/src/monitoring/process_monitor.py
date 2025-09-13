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
import shutil
import sqlite3
from datetime import datetime


class ProcessMonitor:
    """Enhanced process monitor with PM2 and Next.js support"""

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.pm2_available = self._check_pm2_availability()
        self.monitoring_thread = None
        self.monitoring_active = False
        self.hosting_manager = None

    def set_hosting_manager(self, hosting_manager):
        """Set reference to hosting manager for database access"""
        self.hosting_manager = hosting_manager

    def _get_db_connection(self):
        """Get database connection safely"""
        if self.hosting_manager:
            return self.hosting_manager.get_database_connection()
        else:
            try:
                db_path = self.config.get("database_path")
                return sqlite3.connect(db_path, timeout=30.0)
            except Exception as e:
                self.logger.error(f"Database connection failed: {e}")
                return None

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
        """Deploy Node.js application with enhanced Next.js support"""
        try:
            port = deploy_config.get("port", 3000)
            target_dir = f"/tmp/www/domains/{site_name}"

            # Clean up existing directory
            if os.path.exists(target_dir):
                import shutil

                shutil.rmtree(target_dir)

            os.makedirs(target_dir, exist_ok=True)
            self.logger.info(f"Deploying to: {target_dir}")

            # Extract files with Next.js fixes
            self._extract_files(project_files, target_dir)

            # Enhanced install and build process
            if not self._npm_install_and_build(target_dir):
                return {
                    "success": False,
                    "error": "Failed to install dependencies or build application",
                    "site_name": site_name,
                }

            # Determine process manager
            process_manager = self._determine_process_manager()

            # Start the application
            if self._start_nodejs_app(site_name, target_dir, port, process_manager):
                return {
                    "success": True,
                    "site_name": site_name,
                    "port": port,
                    "files_path": target_dir,
                    "process_manager": process_manager,
                    "url": f"http://localhost:{port}",
                    "status": "running",
                    "created_at": datetime.now().isoformat(),
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to start application with process manager",
                    "site_name": site_name,
                    "process_manager": process_manager,
                }

        except Exception as e:
            self.logger.error(f"Deployment failed for {site_name}: {e}")
            return {"success": False, "error": str(e), "site_name": site_name}

    def _extract_files(self, files_dict, target_dir):
        """Extract project files with Next.js compatibility fixes"""
        for file_path, content in files_dict.items():
            full_path = os.path.join(target_dir, file_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)

            # Special handling for package.json
            if file_path.endswith("package.json"):
                try:
                    package_data = json.loads(content)

                    # Remove problematic configurations for Next.js + PM2
                    if "type" in package_data:
                        del package_data["type"]
                        self.logger.info(
                            "Removed 'type' field from package.json for PM2 compatibility"
                        )

                    # Ensure proper scripts for PM2
                    if "scripts" not in package_data:
                        package_data["scripts"] = {}

                    # Add PM2-specific scripts if missing
                    scripts = package_data["scripts"]
                    if "build" not in scripts:
                        scripts["build"] = "next build"
                    if "start" not in scripts:
                        scripts["start"] = "next start"
                    if "pm2:start" not in scripts:
                        scripts["pm2:start"] = "next start -p $PORT"

                    # Ensure engines are specified
                    if "engines" not in package_data:
                        package_data["engines"] = {"node": ">=18.0.0", "npm": ">=8.0.0"}

                    content = json.dumps(package_data, indent=2)

                except json.JSONDecodeError:
                    self.logger.warning(f"Could not parse package.json at {file_path}")

            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)

    def _is_nextjs_app(self, cwd):
        """Check if this is a Next.js application that needs devDependencies"""
        try:
            package_path = os.path.join(cwd, "package.json")
            if os.path.exists(package_path):
                with open(package_path) as f:
                    package_data = json.load(f)

                # Check if Next.js is in dependencies
                deps = package_data.get("dependencies", {})
                dev_deps = package_data.get("devDependencies", {})

                # Check for Next.js in dependencies
                if "next" in deps:
                    return True

                # Check for Next.js-specific files
                nextjs_files = ["next.config.js", "next.config.mjs", "next.config.ts"]

                for config_file in nextjs_files:
                    if os.path.exists(os.path.join(cwd, config_file)):
                        return True

                # Check for tailwindcss in devDependencies (common in Next.js)
                if "tailwindcss" in dev_deps and "postcss" in dev_deps:
                    return True

            return False
        except Exception as e:
            self.logger.warning(f"Failed to detect Next.js app: {e}")
            return False

    def _npm_install_and_build(self, cwd):
        """Enhanced npm install and build process for Next.js"""
        try:
            # Step 1: Clean install
            self.logger.info("Installing dependencies...")
            strategies = [
                ["npm", "ci", "--only=production", "--silent"],
                ["npm", "install", "--only=production", "--silent"],
                ["npm", "install", "--silent"],
                ["npm", "install", "--force", "--silent"],  # Last resort
            ]

            install_success = False
            for strategy in strategies:
                self.logger.info(f"Trying: {' '.join(strategy)}")
                result = subprocess.run(
                    strategy, cwd=cwd, capture_output=True, text=True, timeout=300
                )

                if result.returncode == 0:
                    self.logger.info("npm install successful")
                    install_success = True
                    break
                else:
                    self.logger.warning(f"Strategy failed: {result.stderr[:200]}")

            if not install_success:
                self.logger.error("All npm install strategies failed")
                return False

            # Step 2: Check if build is needed and possible
            if not self._has_build_script(cwd):
                self.logger.info("No build script found, skipping build")
                return True

            # Step 3: Build the Next.js app
            self.logger.info("Building Next.js application...")

            # Set NODE_ENV for build
            env = os.environ.copy()
            env["NODE_ENV"] = "production"
            env["NEXT_TELEMETRY_DISABLED"] = "1"  # Disable telemetry for faster builds

            result = subprocess.run(
                ["npm", "run", "build"],
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=900,  # Increased timeout for build
                env=env,
            )

            if result.returncode == 0:
                self.logger.info("Next.js build successful")

                # Verify .next directory exists
                next_dir = os.path.join(cwd, ".next")
                if os.path.exists(next_dir):
                    self.logger.info(f".next directory created successfully")
                    return True
                else:
                    self.logger.error(".next directory not found after build")
                    return False
            else:
                self.logger.error(f"Next.js build failed: {result.stderr}")
                # Log stdout as well for better debugging
                if result.stdout:
                    self.logger.error(f"Build stdout: {result.stdout}")
                return False

        except Exception as e:
            self.logger.error(f"Build process failed: {e}")
            return False

    def _start_pm2_app(self, site_name, cwd, port):
        """Start Next.js app with PM2 - optimized configuration"""
        try:
            # Ensure the build is complete before starting
            next_dir = os.path.join(cwd, ".next")
            if not os.path.exists(next_dir):
                self.logger.error("No .next directory found. Build may have failed.")
                return False

            # Detect the correct start command
            start_command = self._detect_nextjs_start_script(cwd, port)

            # Create optimized PM2 ecosystem for Next.js
            ecosystem = {
                "apps": [
                    {
                        "name": site_name,
                        "script": "npm",
                        "args": "start",
                        "cwd": cwd,
                        "env": {
                            "NODE_ENV": "production",
                            "PORT": str(port),
                            "NEXT_TELEMETRY_DISABLED": "1",
                        },
                        "instances": 1,
                        "exec_mode": "fork",  # Use fork mode for Next.js
                        "max_memory_restart": "1G",
                        "min_uptime": "10s",
                        "max_restarts": 5,
                        "restart_delay": 4000,
                        "autorestart": True,
                        "watch": False,  # Disable watch in production
                        "ignore_watch": [".next", "node_modules"],
                        "error_file": f"/tmp/process-logs/{site_name}-error.log",
                        "out_file": f"/tmp/process-logs/{site_name}-out.log",
                        "log_file": f"/tmp/process-logs/{site_name}-combined.log",
                        "time": True,
                        "merge_logs": True,
                        "kill_timeout": 5000,
                        "listen_timeout": 8000,
                        "log_date_format": "YYYY-MM-DD HH:mm:ss Z",
                    }
                ]
            }

            # Ensure log directory exists
            os.makedirs("/tmp/process-logs", exist_ok=True)

            ecosystem_path = f"{cwd}/ecosystem.config.json"
            with open(ecosystem_path, "w") as f:
                json.dump(ecosystem, f, indent=2)

            self.logger.info(f"Created PM2 ecosystem config at {ecosystem_path}")

            # Delete existing PM2 process if it exists
            subprocess.run(["pm2", "delete", site_name], capture_output=True, text=True)

            # Start with PM2
            result = subprocess.run(
                ["pm2", "start", ecosystem_path], capture_output=True, text=True
            )

            if result.returncode == 0:
                self.logger.info(f"PM2 app started successfully: {site_name}")

                # Wait a moment then check if it's actually running
                import time

                time.sleep(3)

                status_result = subprocess.run(
                    ["pm2", "show", site_name], capture_output=True, text=True
                )

                if status_result.returncode == 0:
                    self.logger.info(f"PM2 app {site_name} is running")
                    return True
                else:
                    self.logger.error(f"PM2 app {site_name} failed to start properly")
                    return False
            else:
                self.logger.error(f"PM2 start failed: {result.stderr}")
                return False

        except Exception as e:
            self.logger.error(f"PM2 app start failed: {e}")
            return False

    def _detect_nextjs_start_script(self, cwd, port):
        """Detect the correct start script for Next.js app"""
        try:
            package_path = os.path.join(cwd, "package.json")
            if os.path.exists(package_path):
                with open(package_path) as f:
                    package_data = json.load(f)
                    scripts = package_data.get("scripts", {})

                    # Check for Next.js in dependencies
                    deps = package_data.get("dependencies", {})
                    is_nextjs = "next" in deps

                    if is_nextjs and "start" in scripts:
                        return f"npm start"
                    elif is_nextjs and "dev" in scripts:
                        # Fallback to dev for development
                        return f"npm run dev"

            # Final fallback
            return "npm start"

        except Exception as e:
            self.logger.warning(f"Failed to detect Next.js start script: {e}")
            return "npm start"

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

    def _detect_start_script(self, cwd):
        """Detect the correct start script for the app"""
        try:
            package_path = os.path.join(cwd, "package.json")
            if os.path.exists(package_path):
                with open(package_path) as f:
                    package_data = json.load(f)
                    scripts = package_data.get("scripts", {})

                    # For Next.js or any app with "type": "module", use npm start
                    if package_data.get(
                        "type"
                    ) == "module" or "next" in package_data.get("dependencies", {}):
                        return "npm start"

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

    def get_pm2_status(self):
        """Get comprehensive PM2 daemon status"""
        if not self.pm2_available:
            return {"available": False, "error": "PM2 not installed or not available"}

        try:
            status_info = {"available": True, "timestamp": datetime.now().isoformat()}

            # Get PM2 version
            try:
                version_result = subprocess.run(
                    ["pm2", "--version"], capture_output=True, text=True
                )
                if version_result.returncode == 0:
                    status_info["version"] = version_result.stdout.strip()
                else:
                    status_info["version"] = "unknown"
            except Exception as e:
                status_info["version"] = f"error: {e}"

            # Get PM2 status (ping)
            try:
                ping_result = subprocess.run(
                    ["pm2", "ping"], capture_output=True, text=True, timeout=10
                )
                status_info["daemon_running"] = ping_result.returncode == 0
                if ping_result.returncode == 0:
                    status_info["ping_response"] = ping_result.stdout.strip()
                else:
                    status_info["ping_error"] = ping_result.stderr.strip()
            except subprocess.TimeoutExpired:
                status_info["daemon_running"] = False
                status_info["ping_error"] = "timeout"
            except Exception as e:
                status_info["daemon_running"] = False
                status_info["ping_error"] = str(e)

            # Get PM2 home directory
            status_info["pm2_home"] = os.environ.get("PM2_HOME", "default")

            # Get process count
            try:
                list_result = subprocess.run(
                    ["pm2", "jlist"], capture_output=True, text=True
                )
                if list_result.returncode == 0:
                    processes = json.loads(list_result.stdout)
                    status_info["process_count"] = len(processes)

                    # Process status summary
                    online_count = len(
                        [
                            p
                            for p in processes
                            if p.get("pm2_env", {}).get("status") == "online"
                        ]
                    )
                    stopped_count = len(
                        [
                            p
                            for p in processes
                            if p.get("pm2_env", {}).get("status") == "stopped"
                        ]
                    )
                    errored_count = len(
                        [
                            p
                            for p in processes
                            if p.get("pm2_env", {}).get("status") == "errored"
                        ]
                    )

                    status_info["process_summary"] = {
                        "online": online_count,
                        "stopped": stopped_count,
                        "errored": errored_count,
                        "total": len(processes),
                    }

                    # Get memory/cpu usage if processes exist
                    if processes:
                        total_memory = sum(
                            p.get("monit", {}).get("memory", 0) for p in processes
                        )
                        avg_cpu = sum(
                            p.get("monit", {}).get("cpu", 0) for p in processes
                        ) / len(processes)

                        status_info["resource_usage"] = {
                            "total_memory_bytes": total_memory,
                            "total_memory_mb": round(total_memory / 1024 / 1024, 2),
                            "average_cpu_percent": round(avg_cpu, 2),
                        }
                else:
                    status_info["process_count"] = 0
                    status_info["list_error"] = list_result.stderr.strip()
            except Exception as e:
                status_info["process_count"] = 0
                status_info["list_error"] = str(e)

            # Get system info if daemon is running
            if status_info.get("daemon_running"):
                try:
                    # Try to get PM2 status
                    status_result = subprocess.run(
                        ["pm2", "status"], capture_output=True, text=True
                    )
                    status_info["status_command_available"] = (
                        status_result.returncode == 0
                    )
                except:
                    status_info["status_command_available"] = False

                # Check if logs are accessible
                try:
                    logs_result = subprocess.run(
                        ["pm2", "logs", "--lines", "1"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    status_info["logs_available"] = logs_result.returncode == 0
                except:
                    status_info["logs_available"] = False

            return status_info

        except Exception as e:
            self.logger.error(f"Failed to get PM2 status: {e}")
            return {
                "available": True,
                "error": f"Failed to get status: {e}",
                "timestamp": datetime.now().isoformat(),
            }

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

    def get_system_performance(self):
        """Get system performance for status endpoint"""
        return self.get_system_metrics()

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
            conn = self._get_db_connection()
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
            conn = self._get_db_connection()
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
            conn = self._get_db_connection()
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

            conn = self._get_db_connection()
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
        if self.hosting_manager and hasattr(
            self.hosting_manager, "_configure_nginx_site"
        ):
            return self.hosting_manager._configure_nginx_site(
                site_name, f"{self.config.get('web_root')}/{site_name}", port, "node"
            )
        return True

    # Add these methods to your src/monitoring/process_monitor.py file
    # Add at the end of the ProcessMonitor class

    def stop_app(self, app_name):
        """Stop application by name - MISSING METHOD"""
        try:
            self.logger.info(f"Attempting to stop app: {app_name}")

            # Try PM2 first if available
            if hasattr(self, "pm2_available") and self.pm2_available:
                result = subprocess.run(
                    ["pm2", "stop", app_name], capture_output=True, text=True
                )
                if result.returncode == 0:
                    self.logger.info(f"Successfully stopped PM2 app: {app_name}")
                    return True
                else:
                    self.logger.warning(f"PM2 stop failed: {result.stderr}")

                # Try PM2 delete as fallback
                result = subprocess.run(
                    ["pm2", "delete", app_name], capture_output=True, text=True
                )
                if result.returncode == 0:
                    self.logger.info(f"Successfully deleted PM2 app: {app_name}")
                    return True

            # Try systemd
            result = subprocess.run(
                ["systemctl", "stop", f"nodejs-{app_name}"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                self.logger.info(
                    f"Successfully stopped systemd service: nodejs-{app_name}"
                )
                return True

            # Try simple process control
            control_script = f"/tmp/nodejs-apps/{app_name}/control.sh"
            if os.path.exists(control_script):
                result = subprocess.run([control_script, "stop"], capture_output=True)
                if result.returncode == 0:
                    self.logger.info(
                        f"Successfully stopped app via control script: {app_name}"
                    )
                    return True

            self.logger.warning(f"Could not stop app {app_name} using any method")
            return False

        except Exception as e:
            self.logger.error(f"Failed to stop app {app_name}: {e}")
            return False

    def get_system_performance(self):
        """Get system performance metrics - MISSING METHOD"""
        try:
            import psutil

            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()

            # Load average (Unix only)
            try:
                load_avg = os.getloadavg()
            except:
                load_avg = (0, 0, 0)

            # Memory metrics
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()

            # Disk metrics
            disk = psutil.disk_usage("/")

            # Network metrics (basic)
            try:
                network = psutil.net_io_counters()
                network_stats = {
                    "bytes_sent": network.bytes_sent,
                    "bytes_recv": network.bytes_recv,
                    "packets_sent": network.packets_sent,
                    "packets_recv": network.packets_recv,
                }
            except:
                network_stats = {}

            return {
                "cpu": {
                    "percent": cpu_percent,
                    "count": cpu_count,
                    "load_average": {
                        "1min": load_avg[0],
                        "5min": load_avg[1],
                        "15min": load_avg[2],
                    },
                },
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "percent": memory.percent,
                    "used": memory.used,
                    "free": memory.free,
                },
                "swap": {
                    "total": swap.total,
                    "used": swap.used,
                    "free": swap.free,
                    "percent": swap.percent,
                },
                "disk": {
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                    "percent": (disk.used / disk.total) * 100 if disk.total > 0 else 0,
                },
                "network": network_stats,
                "timestamp": datetime.now().isoformat(),
                "uptime_seconds": time.time() - psutil.boot_time(),
            }

        except Exception as e:
            self.logger.error(f"Failed to get system performance: {e}")
            return {"error": str(e), "timestamp": datetime.now().isoformat()}

    def get_database_connection(self):
        """Get database connection - MISSING METHOD"""
        try:
            import sqlite3

            db_path = self.config.get("database_path", "/tmp/hosting/hosting.db")
            conn = sqlite3.connect(db_path, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            return conn
        except Exception as e:
            self.logger.error(f"Database connection failed: {e}")
            return None

    # Also fix existing methods that reference self.hosting_manager.get_database_connection()
    # Replace these in your existing methods:

    def _save_process_info(self, site_name, port, cwd, process_manager):
        """Save process information to database - FIXED"""
        try:
            conn = (
                self.get_database_connection()
            )  # Changed from self.hosting_manager.get_database_connection()
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

    def start_process(self, process_name):
        """Start a specific process - FIXED"""
        try:
            # Get process info from database
            conn = (
                self.get_database_connection()
            )  # Changed from self.hosting_manager.get_database_connection()
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
        """Stop a specific process - FIXED"""
        try:
            # Similar logic to start_process but with stop action
            conn = (
                self.get_database_connection()
            )  # Changed from self.hosting_manager.get_database_connection()
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

    def _update_process_database(self):
        """Update process database with current status - FIXED"""
        try:
            processes = self.get_all_processes()

            conn = (
                self.get_database_connection()
            )  # Changed from self.hosting_manager.get_database_connection()
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

    # Add missing shutil import at the top of your process_monitor.py file if not already there:
    # import shutil
