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

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

# Import all required modules (no API server needed)
from core.hosting_manager import HostingManager
from monitoring.process_monitor import ProcessMonitor
from monitoring.health_checker import HealthChecker
from api.app import HostingAPI
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

        # Set up cross-references
        self.process_monitor.set_hosting_manager(self.hosting_manager)

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
        """Start the full API server (not the minimal stub)"""
        try:
            api = HostingAPI(
                hosting_manager=self.hosting_manager,
                process_monitor=self.process_monitor,
                health_checker=self.health_checker,
                config=self.config,
                logger=self.logger,
            )
            api.run(host=host, port=port)
        except Exception as e:
            self.logger.error(f"API server failed: {e}", exc_info=True)
            sys.exit(1)

    def start_monitoring(self):
        """Start monitoring services"""
        try:
            self.logger.info("Starting monitoring services...")

            # Start background monitoring if available
            if hasattr(self.process_monitor, "start_background_monitoring"):
                self.process_monitor.start_background_monitoring()

            if hasattr(self.health_checker, "start_background_checks"):
                self.health_checker.start_background_checks()

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
        print(
            f"Nginx: {'Running' if status.get('nginx_running', False) else 'Stopped'}"
        )
        print(
            f"Database: {'Connected' if status.get('database_connected', False) else 'Failed'}"
        )
        print(f"Active domains: {status.get('domain_count', 0)}")
        print(f"Running apps: {status.get('active_apps', 0)}")

        # Process details
        try:
            processes = self.process_monitor.get_all_processes()
            if processes:
                print(f"\nRunning Processes:")
                for proc in processes:
                    status_icon = "✓" if proc.get("status") == "online" else "✗"
                    print(
                        f"  {status_icon} {proc.get('name', 'Unknown')} (PID: {proc.get('pid', 'N/A')}) - {proc.get('memory', 'N/A')}"
                    )
            else:
                print("\nNo processes found")
        except Exception as e:
            print(f"Error getting process details: {e}")


def main():
    parser = argparse.ArgumentParser(description="Hosting Manager v3.0")
    parser.add_argument("--setup", action="store_true", help="Setup system")
    parser.add_argument("--api", action="store_true", help="Start minimal API server")
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

    try:
        app = HostingApplication()
    except Exception as e:
        print(f"FATAL: Failed to initialize application: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    try:
        if args.setup:
            success = app.setup_system()
            sys.exit(0 if success else 1)

        elif args.api:
            app.start_api_server(host=args.api_host, port=args.api_port)

        elif args.monitor:
            app.start_monitoring()
            print("Monitoring started. Press Ctrl+C to stop.")
            try:
                import time

                while True:
                    time.sleep(60)
            except KeyboardInterrupt:
                print("\nMonitoring stopped")

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
            domains = app.hosting_manager.list_domains()
            print("\nActive Domains:")
            if domains:
                for domain in domains:
                    print(
                        f"  {domain['domain_name']} (Port: {domain['port']}, Type: {domain['site_type']})"
                    )
            else:
                print("  No active domains found")

        else:
            print("Hosting Manager v3.0 - Modular Architecture (API Refactored)")
            print("=" * 60)
            print("\nCommands:")
            print("  --setup                 Complete system setup")
            print("  --api                   Start minimal API server")
            print("  --monitor              Start monitoring services")
            print("  --status               Show system status")
            print("\nLegacy commands:")
            print("  deploy <domain> <port> [type]    Deploy domain")
            print("  remove <domain>                  Remove domain")
            print("  list                             List domains")
            print("\nNote: Full API functionality was refactored out.")
            print("Use --api for basic health checks and monitoring.")

    except KeyboardInterrupt:
        print("\nShutdown requested")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
