#!/usr/bin/env python3
"""
Modular Hosting Manager v3.0
Main application entry point with improved monitoring and PM2 support
"""

import os
import sys
import argparse
import json
from datetime import datetime
import shutil

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from core.hosting_manager import HostingManager
from api.server import HostingAPI
from monitoring.process_monitor import ProcessMonitor
from monitoring.health_checker import HealthChecker
from utils.config import Config
from utils.logger import Logger


class HostingApplication:
    """Main hosting application orchestrator"""

    def __init__(self):
        self.config = Config()
        self.logger = Logger()
        self.hosting_manager = HostingManager(self.config, self.logger)
        self.process_monitor = ProcessMonitor(self.config, self.logger)
        self.health_checker = HealthChecker(self.config, self.logger)

    def setup_system(self):
        """Complete system setup"""
        self.logger.info("Starting hosting manager system setup...")

        try:
            # Initialize core system
            if not self.hosting_manager.setup_system():
                self.logger.error("Core system setup failed")
                return False

            # Setup monitoring
            if not self.process_monitor.setup():
                self.logger.warning("Process monitor setup had issues")

            # Setup health checking
            if not self.health_checker.setup():
                self.logger.warning("Health checker setup had issues")

            self.logger.info("System setup completed successfully")
            return True

        except Exception as e:
            self.logger.error(f"System setup failed: {e}")
            return False

    def start_api_server(self, host="0.0.0.0", port=5000):
        """Start the API server"""
        try:
            api = HostingAPI(
                self.hosting_manager,
                self.process_monitor,
                self.health_checker,
                self.config,
                self.logger,
            )

            self.logger.info(f"Starting API server on {host}:{port}")
            api.run(host=host, port=port)

        except Exception as e:
            self.logger.error(f"API server failed: {e}")
            sys.exit(1)

    def start_monitoring(self):
        """Start monitoring services"""
        try:
            self.logger.info("Starting monitoring services...")

            # Start process monitor
            self.process_monitor.start()

            # Start health checker
            self.health_checker.start()

            self.logger.info("Monitoring services started")

        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")

    def show_status(self):
        """Show system status"""
        print("\nHosting Manager Status v3.0")
        print("=" * 50)

        # System info
        print(f"Read-only mode: {self.hosting_manager.readonly_filesystem}")
        print(f"Web root: {self.config.get('web_root')}")
        print(f"Database: {self.config.get('database_path')}")

        # Services status
        status = self.hosting_manager.get_system_status()
        print(f"Nginx: {'Running' if status['nginx_running'] else 'Stopped'}")
        print(f"Database: {'Connected' if status['database_connected'] else 'Failed'}")
        print(f"Active domains: {status['domain_count']}")
        print(f"Running apps: {status['active_apps']}")

        # Process details
        processes = self.process_monitor.get_all_processes()
        if processes:
            print(f"\nRunning Processes:")
            for proc in processes:
                status_icon = "✓" if proc["status"] == "online" else "✗"
                print(
                    f"  {status_icon} {proc['name']} (PID: {proc.get('pid', 'N/A')}) - {proc.get('memory', 'N/A')}"
                )


def main():
    parser = argparse.ArgumentParser(description="Hosting Manager v3.0")
    parser.add_argument("--setup", action="store_true", help="Setup system")
    parser.add_argument("--api", action="store_true", help="Start API server")
    parser.add_argument("--monitor", action="store_true", help="Start monitoring only")
    parser.add_argument("--status", action="store_true", help="Show system status")
    parser.add_argument("--api-port", type=int, default=5000, help="API server port")
    parser.add_argument("--api-host", default="0.0.0.0", help="API server host")

    # Legacy command support
    parser.add_argument("command", nargs="?", help="Legacy command")
    parser.add_argument("domain", nargs="?", help="Domain name")
    parser.add_argument("port", nargs="?", type=int, help="Port number")
    parser.add_argument("site_type", nargs="?", default="static", help="Site type")

    args = parser.parse_args()

    app = HostingApplication()

    try:
        if args.setup:
            success = app.setup_system()
            sys.exit(0 if success else 1)

        elif args.api:
            app.start_api_server(host=args.api_host, port=args.api_port)

        elif args.monitor:
            app.start_monitoring()

        elif args.status:
            app.show_status()

        # Legacy commands
        elif args.command == "deploy" and args.domain and args.port:
            success = app.hosting_manager.deploy_domain(
                args.domain, args.port, args.site_type
            )
            sys.exit(0 if success else 1)

        elif args.command == "remove" and args.domain:
            success = app.hosting_manager.remove_domain(args.domain)
            sys.exit(0 if success else 1)

        elif args.command == "list":
            app.hosting_manager.list_domains()

        else:
            print("Hosting Manager v3.0 - Modular Architecture")
            print("=" * 50)
            print("\nCommands:")
            print("  --setup                 Complete system setup")
            print("  --api                   Start API server")
            print("  --monitor              Start monitoring services")
            print("  --status               Show system status")
            print("\nDevelopment:")
            print("  Use deployment-setup.sh for better workflow")
            print("  ./deployment-setup.sh full-setup")
            print("  ./deployment-setup.sh watch")

    except KeyboardInterrupt:
        print("\nShutdown requested")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
