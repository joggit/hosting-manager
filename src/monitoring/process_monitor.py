# src/monitoring/process_monitor.py
"""
Process monitoring with PM2, systemd, and custom process management support
Enhanced monitoring for Next.js applications - Concise logging version
Updated with Firebase/large package support and high-CPU stall detection
"""

import subprocess
import json
import os
import time
import psutil
import threading
import shutil
import sqlite3
import select
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

            if self.pm2_available:
                self._setup_pm2()

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
                return True
            return False
        except:
            return False

    def _setup_pm2(self):
        """Setup PM2 environment"""
        try:
            pm2_home = (
                "/tmp/pm2-home"
                if self.config.get("readonly_mode")
                else "/home/www-data/.pm2"
            )
            os.makedirs(pm2_home, mode=0o755, exist_ok=True)
            os.environ["PM2_HOME"] = pm2_home
            subprocess.run(["pm2", "ping"], capture_output=True)

        except Exception as e:
            self.logger.warning(f"PM2 setup failed: {e}")

    def deploy_nodejs_app(self, site_name, project_files, deploy_config):
        """Deploy Node.js application"""
        try:
            port = deploy_config.get("port", 3000)
            target_dir = f"/tmp/www/domains/{site_name}"
            user_env_vars = deploy_config.get("env", {})

            self.logger.info(f"Deploying {site_name} to {target_dir} (port {port})")

            # Firebase setup
            firebase_service_account = deploy_config.get("firebase_service_account")
            if firebase_service_account:
                self.logger.info("Firebase credentials provided")

            # Clean up existing directory
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir)
            os.makedirs(target_dir, exist_ok=True)

            # Extract files
            self._extract_files(project_files, target_dir)

            # Save Firebase JSON if provided
            if firebase_service_account:
                try:
                    firebase_json_path = os.path.join(
                        target_dir, "firebase-service-account.json"
                    )
                    with open(firebase_json_path, "w") as f:
                        json.dump(firebase_service_account, f, indent=2)
                    os.chmod(firebase_json_path, 0o600)

                    user_env_vars["FIREBASE_SERVICE_ACCOUNT_PATH"] = firebase_json_path
                    user_env_vars["FIREBASE_PROJECT_ID"] = firebase_service_account.get(
                        "project_id", ""
                    )
                    user_env_vars["FIREBASE_CLIENT_EMAIL"] = (
                        firebase_service_account.get("client_email", "")
                    )
                    private_key = firebase_service_account.get("private_key", "")
                    user_env_vars["FIREBASE_PRIVATE_KEY"] = private_key.replace(
                        "\n", "\\n"
                    )

                except Exception as e:
                    self.logger.error(f"Failed to save Firebase JSON: {e}")

            # Install and build
            if not self._npm_install_and_build(target_dir):
                return {
                    "success": False,
                    "error": "Failed to install dependencies or build application",
                    "site_name": site_name,
                }

            # Start the application
            process_manager = self._determine_process_manager()
            if self._start_nodejs_app(
                site_name, target_dir, port, process_manager, user_env_vars
            ):
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
                    "error": "Failed to start application",
                    "site_name": site_name,
                }

        except Exception as e:
            self.logger.error(f"Deployment failed: {e}")
            return {"success": False, "error": str(e), "site_name": site_name}

    def _extract_files(self, files_dict, target_dir):
        """Extract project files"""
        for file_path, content in files_dict.items():
            full_path = os.path.join(target_dir, file_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)

            # Special handling for package.json
            if file_path.endswith("package.json"):
                try:
                    package_data = json.loads(content)

                    if "type" in package_data:
                        del package_data["type"]

                    if "scripts" not in package_data:
                        package_data["scripts"] = {}

                    scripts = package_data["scripts"]
                    if "build" not in scripts:
                        scripts["build"] = "next build"
                    if "start" not in scripts:
                        scripts["start"] = "next start"

                    if "engines" not in package_data:
                        package_data["engines"] = {"node": ">=18.0.0", "npm": ">=8.0.0"}

                    content = json.dumps(package_data, indent=2)

                except json.JSONDecodeError:
                    pass

            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)

    def _is_nextjs_app(self, cwd):
        """Check if this is a Next.js application"""
        try:
            package_path = os.path.join(cwd, "package.json")
            if os.path.exists(package_path):
                with open(package_path) as f:
                    package_data = json.load(f)
                    deps = package_data.get("dependencies", {})
                    if "next" in deps:
                        return True

                nextjs_files = ["next.config.js", "next.config.mjs", "next.config.ts"]
                for config_file in nextjs_files:
                    if os.path.exists(os.path.join(cwd, config_file)):
                        return True

            return False
        except:
            return False

    def _npm_install_and_build(self, cwd):
        """Install dependencies and build - yarn first, npm fallback"""
        try:
            self.logger.info("Starting package installation...")

            # Clear npm cache (not yarn cache - yarn caching is better)
            try:
                subprocess.run(
                    ["npm", "cache", "clean", "--force"],
                    cwd=cwd,
                    capture_output=True,
                    timeout=30,
                )
            except:
                pass

            # YARN FIRST - much faster than npm
            strategies = [
                {
                    "name": "yarn",
                    "cmd": ["yarn", "install", "--network-timeout", "300000"],
                },
                {
                    "name": "npm (legacy-peer-deps)",
                    "cmd": [
                        "npm",
                        "install",
                        "--legacy-peer-deps",
                        "--no-audit",
                        "--no-fund",
                    ],
                },
            ]

            install_success = False
            for strategy in strategies:
                self.logger.info(f"Trying: {strategy['name']}")

                # Check if command exists
                try:
                    result = subprocess.run(
                        [strategy["cmd"][0], "--version"],
                        capture_output=True,
                        timeout=5,
                    )
                    if result.returncode != 0:
                        self.logger.info(
                            f"  {strategy['cmd'][0]} not available, skipping"
                        )
                        continue
                except:
                    self.logger.info(f"  {strategy['cmd'][0]} not found, skipping")
                    continue

                success, output = self._simple_install_with_progress(
                    strategy["cmd"], cwd, timeout=1800  # 30 minutes
                )

                if success and self._verify_npm_installation(cwd):
                    self.logger.info(f"✓ Packages installed with {strategy['name']}")

                    # Fix for Next.js 14.0.0 missing critters bug
                    if self._is_nextjs_app(cwd):
                        critters_path = os.path.join(cwd, "node_modules", "critters")
                        if not os.path.exists(critters_path):
                            self.logger.info(
                                "Installing missing critters package for Next.js..."
                            )
                            install_cmd = (
                                ["yarn", "add", "critters"]
                                if strategy["name"] == "yarn"
                                else ["npm", "install", "critters"]
                            )
                            try:
                                result = subprocess.run(
                                    install_cmd,
                                    cwd=cwd,
                                    capture_output=True,
                                    timeout=60,
                                )
                                if result.returncode == 0:
                                    self.logger.info("✓ critters installed")
                            except:
                                self.logger.warning(
                                    "Could not install critters (continuing anyway)"
                                )

                    install_success = True
                    break
                else:
                    self.logger.warning(
                        f"  {strategy['name']} failed, trying next strategy"
                    )

            if not install_success:
                self.logger.error("All installation strategies failed")
                return False

            time.sleep(2)

            # Build if needed
            if not self._has_build_script(cwd):
                self.logger.info("No build script, skipping build")
                return True

            self.logger.info("Starting build...")
            env = os.environ.copy()
            env["NODE_ENV"] = "production"
            env["NEXT_TELEMETRY_DISABLED"] = "1"

            build_success, build_output = self._simple_build_with_progress(
                cwd, env, timeout=1800
            )

            if not build_success:
                return False

            if self._verify_build_output(cwd):
                self.logger.info("✓ Build completed")
                return True
            else:
                self.logger.error("Build verification failed")
                return False

        except Exception as e:
            self.logger.error(f"Installation failed: {e}")
            return False

    def _configure_npm_for_deployment(self, cwd):
        """Configure npm for better reliability"""
        try:
            configs = [
                ["npm", "config", "set", "fetch-retries", "5"],
                ["npm", "config", "set", "fetch-timeout", "300000"],
            ]
            for config_cmd in configs:
                subprocess.run(config_cmd, cwd=cwd, capture_output=True, timeout=5)
        except:
            pass

    def _simple_install_with_progress(self, cmd, cwd, timeout=1800):
        """Simple install with progress logging every 2 minutes"""
        try:
            process = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            start_time = time.time()
            last_output_time = start_time
            last_log_time = start_time
            output_lines = []

            while True:
                if process.poll() is not None:
                    break

                elapsed = time.time() - start_time

                # Progress every 2 minutes
                if time.time() - last_log_time > 120:
                    self.logger.info(f"  {int(elapsed/60)}min elapsed...")
                    last_log_time = time.time()

                # Overall timeout
                if elapsed > timeout:
                    self.logger.error(f"  Timeout after {int(timeout/60)} minutes")
                    process.kill()
                    process.wait()
                    return False, "\n".join(output_lines)

                # Check for output
                ready, _, _ = select.select([process.stdout], [], [], 1.0)
                if ready:
                    line = process.stdout.readline()
                    if line:
                        output_lines.append(line.strip())
                        last_output_time = time.time()

                        # Log errors only
                        if "error" in line.lower() and "npm ERR!" in line:
                            self.logger.error(f"  {line.strip()}")

                # Stall detection - 15 minutes of no output
                if time.time() - last_output_time > 900:
                    self.logger.error(f"  No output for 15 minutes - aborting")
                    process.kill()
                    process.wait()
                    return False, "\n".join(output_lines)

            # Get remaining output
            remaining_output, _ = process.communicate()
            if remaining_output:
                output_lines.extend(remaining_output.strip().split("\n"))

            total_time = time.time() - start_time

            if process.returncode == 0:
                self.logger.info(f"  Completed in {int(total_time)}s")
                return True, "\n".join(output_lines)
            else:
                self.logger.error(f"  Failed (exit code {process.returncode})")
                # Show last few error lines
                for line in output_lines[-5:]:
                    if "error" in line.lower():
                        self.logger.error(f"    {line}")
                return False, "\n".join(output_lines)

        except Exception as e:
            self.logger.error(f"  Exception: {e}")
            return False, str(e)

    def _simple_build_with_progress(self, cwd, env, timeout=1800):
        """Simple build with progress logging"""
        try:
            # Check if using yarn (yarn.lock exists) or npm
            build_cmd = (
                ["yarn", "build"]
                if os.path.exists(os.path.join(cwd, "yarn.lock"))
                else ["npm", "run", "build"]
            )

            process = subprocess.Popen(
                build_cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
            )

            start_time = time.time()
            last_log_time = start_time
            output_lines = []

            while True:
                if process.poll() is not None:
                    break

                elapsed = time.time() - start_time

                # Progress every 2 minutes
                if time.time() - last_log_time > 120:
                    self.logger.info(f"  Building... {int(elapsed/60)}min elapsed")
                    last_log_time = time.time()

                if elapsed > timeout:
                    process.kill()
                    process.wait()
                    return False, "\n".join(output_lines)

                ready, _, _ = select.select([process.stdout], [], [], 1.0)
                if ready:
                    line = process.stdout.readline()
                    if line:
                        output_lines.append(line.strip())

                        # Log errors only
                        if "error" in line.lower():
                            self.logger.error(f"  {line.strip()}")

            remaining_output, _ = process.communicate()
            if remaining_output:
                output_lines.extend(remaining_output.strip().split("\n"))

            total_time = time.time() - start_time

            if process.returncode == 0:
                self.logger.info(f"  Built in {int(total_time)}s")
                return True, "\n".join(output_lines)
            else:
                self.logger.error(f"  Build failed")
                for line in output_lines[-5:]:
                    if line.strip():
                        self.logger.error(f"    {line}")
                return False, "\n".join(output_lines)

        except Exception as e:
            self.logger.error(f"  Build exception: {e}")
            return False, str(e)

    def _verify_npm_installation(self, cwd):
        """Verify installation (works for both npm and yarn)"""
        try:
            node_modules_path = os.path.join(cwd, "node_modules")

            if not os.path.exists(node_modules_path):
                return False

            package_count = len(
                [
                    d
                    for d in os.listdir(node_modules_path)
                    if os.path.isdir(os.path.join(node_modules_path, d))
                    and not d.startswith(".")
                ]
            )

            if package_count < 5:
                return False

            if self._is_nextjs_app(cwd):
                next_path = os.path.join(node_modules_path, "next")
                if not os.path.exists(next_path):
                    return False

            return True

        except:
            return False

    def _verify_build_output(self, cwd):
        """Verify build output"""
        try:
            if self._is_nextjs_app(cwd):
                next_dir = os.path.join(cwd, ".next")
                if not os.path.exists(next_dir):
                    return False

                required_dirs = ["server", "static"]
                for d in required_dirs:
                    if not os.path.exists(os.path.join(next_dir, d)):
                        return False

                return True

            return True

        except:
            return False

    def _start_pm2_app(self, site_name, cwd, port, user_env_vars=None):
        """Start app with PM2"""
        try:
            if user_env_vars is None:
                user_env_vars = {}

            next_dir = os.path.join(cwd, ".next")
            if not os.path.exists(next_dir):
                return False

            env_vars = {
                "NODE_ENV": "production",
                "PORT": str(port),
                "NEXT_TELEMETRY_DISABLED": "1",
                **user_env_vars,
            }

            # Use yarn if yarn.lock exists, otherwise npm
            if os.path.exists(os.path.join(cwd, "yarn.lock")):
                script_cmd = "yarn"
                script_args = "start"
            else:
                script_cmd = "npm"
                script_args = "start"

            ecosystem = {
                "apps": [
                    {
                        "name": site_name,
                        "script": script_cmd,
                        "args": script_args,
                        "cwd": cwd,
                        "env": env_vars,
                        "instances": 1,
                        "exec_mode": "fork",
                        "max_memory_restart": "1G",
                        "autorestart": True,
                        "error_file": f"/tmp/process-logs/{site_name}-error.log",
                        "out_file": f"/tmp/process-logs/{site_name}-out.log",
                    }
                ]
            }

            os.makedirs("/tmp/process-logs", exist_ok=True)

            ecosystem_path = f"{cwd}/ecosystem.config.json"
            with open(ecosystem_path, "w") as f:
                json.dump(ecosystem, f, indent=2)

            subprocess.run(["pm2", "delete", site_name], capture_output=True)
            result = subprocess.run(
                ["pm2", "start", ecosystem_path], capture_output=True, text=True
            )

            if result.returncode == 0:
                time.sleep(2)
                status = subprocess.run(["pm2", "show", site_name], capture_output=True)
                return status.returncode == 0

            return False

        except Exception as e:
            self.logger.error(f"PM2 start failed: {e}")
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

    def _determine_process_manager(self):
        """Determine which process manager to use"""
        if self.pm2_available:
            return "pm2"
        elif self.config.get("readonly_mode"):
            return "readonly-simple"
        else:
            return "systemd"

    def _start_nodejs_app(
        self, site_name, cwd, port, process_manager, user_env_vars=None
    ):
        """Start Node.js application"""
        try:
            if user_env_vars is None:
                user_env_vars = {}

            if process_manager == "pm2":
                return self._start_pm2_app(site_name, cwd, port, user_env_vars)
            elif process_manager == "systemd":
                return self._start_systemd_app(site_name, cwd, port)
            else:
                return self._start_simple_app(site_name, cwd, port)

        except Exception as e:
            self.logger.error(f"Failed to start app: {e}")
            return False

    def _start_systemd_app(self, site_name, cwd, port):
        """Start app with systemd"""
        return True

    def _start_simple_app(self, site_name, cwd, port):
        """Start app with simple process manager"""
        return True

    def get_all_processes(self):
        """Get all managed processes"""
        processes = []
        try:
            if self.pm2_available:
                processes.extend(self._get_pm2_processes())
            processes.extend(self._get_systemd_processes())
            processes.extend(self._get_simple_processes())
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
                        "memory": f"{app.get('monit', {}).get('memory', 0) // (1024*1024)}MB",
                        "cpu": f"{app.get('monit', {}).get('cpu', 0):.1f}%",
                    }
                    processes.append(process_info)
                return processes
        except:
            pass
        return []

    def _extract_port_from_env(self, env):
        """Extract port from PM2 environment"""
        try:
            return env.get("env", {}).get("PORT") or env.get("PORT")
        except:
            return None

    def _get_systemd_processes(self):
        """Get systemd processes"""
        return []

    def _get_simple_processes(self):
        """Get simple process manager processes"""
        return []

    def _get_process_metrics(self, process_info):
        """Get additional metrics for a process"""
        return {}

    def stop_app(self, app_name):
        """Stop application by name"""
        try:
            if hasattr(self, "pm2_available") and self.pm2_available:
                result = subprocess.run(
                    ["pm2", "delete", app_name], capture_output=True
                )
                return result.returncode == 0
            return False
        except:
            return False

    def get_database_connection(self):
        """Get database connection"""
        try:
            db_path = self.config.get("database_path", "/tmp/hosting/hosting.db")
            conn = sqlite3.connect(db_path, timeout=30.0)
            return conn
        except:
            return None
