#!/usr/bin/env python3
"""
Modular Hosting Manager v3.0
Main application entry point with improved monitoring, PM2 support, and Domain Management
"""

import os
import sys
import argparse
import json
from datetime import datetime

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

# Import all required modules
from core.hosting_manager import HostingManager
from monitoring.process_monitor import ProcessMonitor
from monitoring.health_checker import HealthChecker
from hosting.domain_manager import DomainManager  # NEW: Add domain management
from api.app import HostingAPI  # Import the full modular API
from utils.config import Config
from utils.logger import Logger


class HostingApplication:
    """Main hosting application orchestrator with domain management"""

    def __init__(self):
        self.config = Config()
        self.logger = Logger()
        self.hosting_manager = HostingManager(self.config, self.logger)
        self.process_monitor = ProcessMonitor(self.config, self.logger)
        self.health_checker = HealthChecker(self.config, self.logger)
        self.domain_manager = DomainManager(
            self.config, self.logger
        )  # NEW: Initialize domain manager

        # Set up cross-references
        if hasattr(self.process_monitor, "set_hosting_manager"):
            self.process_monitor.set_hosting_manager(self.hosting_manager)

    def setup_system(self):
        """Complete system setup including domain management"""
        self.logger.info("Starting hosting manager system setup...")

        try:
            # Initialize core system
            if not self.hosting_manager.setup_system():
                self.logger.error("Core system setup failed")
                return False

            # Setup domain management database
            db_connection = self.hosting_manager.get_database_connection()
            if db_connection:
                if not self.domain_manager.setup_database(db_connection):
                    self.logger.warning("Domain management database setup had issues")
                else:
                    self.logger.info("Domain management database setup completed")
                db_connection.close()
            else:
                self.logger.error("Could not get database connection for domain setup")

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
        """Start the full modular API server with domain management"""
        try:
            # Create the full modular API with domain manager
            api = HostingAPI(
                hosting_manager=self.hosting_manager,
                process_monitor=self.process_monitor,
                health_checker=self.health_checker,
                domain_manager=self.domain_manager,  # NEW: Pass domain manager to API
                config=self.config,
                logger=self.logger,
            )
            # Run the API server (this will register all modular routes including domain routes)
            api.run(host=host, port=port)
        except Exception as e:
            self.logger.error(f"API server failed: {e}")
            import traceback

            self.logger.error(f"Traceback: {traceback.format_exc()}")
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
        """Show system status including domain information"""
        print("\nHosting Manager Status v3.0 - Multi-Domain Platform")
        print("=" * 60)

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

        # Domain information
        try:
            available_domains = self.domain_manager.get_available_domains()
            print(f"\nAvailable Parent Domains: {len(available_domains)}")

            total_subdomains = 0
            for domain, config in available_domains.items():
                subdomains = self.domain_manager.list_domains(
                    parent_domain=domain, status="active"
                )
                total_subdomains += len(subdomains)
                print(
                    f"  {config['name']} ({domain}): {len(subdomains)} active subdomains"
                )
                print(
                    f"    Port range: {config['port_range'][0]}-{config['port_range'][1]}"
                )

                # Show first few subdomains
                if subdomains:
                    for i, subdomain in enumerate(subdomains[:3]):
                        print(
                            f"    - {subdomain['domain_name']} (Port: {subdomain['port']})"
                        )
                    if len(subdomains) > 3:
                        print(f"    ... and {len(subdomains) - 3} more")

            print(f"\nTotal active subdomains: {total_subdomains}")

        except Exception as e:
            print(f"Error getting domain details: {e}")

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

    def show_domain_status(self):
        """Show detailed domain status"""
        print("\nDomain Management Status")
        print("=" * 40)

        try:
            available_domains = self.domain_manager.get_available_domains()

            for domain, config in available_domains.items():
                print(f"\n{config['name']} ({domain}):")
                print(f"  Description: {config['description']}")
                print(
                    f"  Port Range: {config['port_range'][0]}-{config['port_range'][1]}"
                )
                print(f"  SSL Enabled: {config['ssl_enabled']}")

                # Get active subdomains
                subdomains = self.domain_manager.list_domains(
                    parent_domain=domain, status="active"
                )
                print(f"  Active Subdomains: {len(subdomains)}")

                if subdomains:
                    for subdomain in subdomains:
                        ssl_status = "SSL" if subdomain.get("ssl_enabled") else "HTTP"
                        print(
                            f"    - {subdomain['domain_name']} (Port: {subdomain['port']}, {ssl_status})"
                        )
                        print(f"      App: {subdomain.get('app_name', 'Unknown')}")
                else:
                    print("    No active subdomains")

        except Exception as e:
            print(f"Error getting domain status: {e}")

    def create_test_subdomain(self, subdomain, parent_domain, app_name="test-app"):
        """Create a test subdomain for testing purposes"""
        try:
            result = self.domain_manager.create_subdomain(
                subdomain, parent_domain, app_name
            )

            if result["success"]:
                print(f"✓ Test subdomain created successfully:")
                print(f"  Domain: {result['domain']}")
                print(f"  Port: {result['port']}")
                print(
                    f"  SSL: {'Enabled' if result.get('ssl_enabled') else 'Disabled'}"
                )
                return True
            else:
                print(f"✗ Failed to create test subdomain: {result['error']}")
                return False

        except Exception as e:
            print(f"✗ Error creating test subdomain: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Hosting Manager v3.0 - Multi-Domain Platform"
    )
    parser.add_argument(
        "--setup", action="store_true", help="Setup system including domain management"
    )
    parser.add_argument(
        "--api",
        action="store_true",
        help="Start full modular API server with domain routes",
    )
    parser.add_argument("--monitor", action="store_true", help="Start monitoring only")
    parser.add_argument("--status", action="store_true", help="Show system status")
    parser.add_argument(
        "--domains", action="store_true", help="Show detailed domain status"
    )
    parser.add_argument("--api-port", type=int, default=5000, help="API server port")
    parser.add_argument("--api-host", default="0.0.0.0", help="API server host")

    # Domain management commands
    parser.add_argument(
        "--test-domain", help="Create test subdomain (format: subdomain.parent-domain)"
    )
    parser.add_argument(
        "--check-domain",
        help="Check subdomain availability (format: subdomain.parent-domain)",
    )

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
            print(
                f"Starting Multi-Domain Hosting API on {args.api_host}:{args.api_port}"
            )
            print("Available domain management endpoints:")
            print("  GET    /api/domains")
            print("  POST   /api/domains/<domain>/subdomains/check")
            print("  POST   /api/deploy/nodejs-domain")
            print("  GET    /api/domains/subdomains")
            print("  DELETE /api/domains/subdomains/<domain>")
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

        elif args.domains:
            app.show_domain_status()

        elif args.test_domain:
            # Parse subdomain.parent-domain format
            parts = args.test_domain.split(".")
            if len(parts) >= 3:  # e.g., "test.smartwave.co.za"
                subdomain = parts[0]
                parent_domain = ".".join(parts[1:])
                app.create_test_subdomain(subdomain, parent_domain)
            else:
                print(
                    "Invalid format. Use: subdomain.parent-domain (e.g., test.smartwave.co.za)"
                )

        elif args.check_domain:
            # Parse and check domain availability
            parts = args.check_domain.split(".")
            if len(parts) >= 3:
                subdomain = parts[0]
                parent_domain = ".".join(parts[1:])
                available, message = app.domain_manager.check_subdomain_availability(
                    subdomain, parent_domain
                )
                status = "Available" if available else "Unavailable"
                print(f"Domain {args.check_domain}: {status} - {message}")
            else:
                print(
                    "Invalid format. Use: subdomain.parent-domain (e.g., test.smartwave.co.za)"
                )

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
            print("Hosting Manager v3.0 - Multi-Domain Platform")
            print("=" * 60)
            print("Supports: smartwave.co.za, datablox.co.za, mondaycafe.co.za")
            print("\nCommands:")
            print(
                "  --setup                    Complete system setup (includes domain management)"
            )
            print(
                "  --api                      Start full API server with domain routes"
            )
            print("  --monitor                  Start monitoring services")
            print("  --status                   Show system status")
            print("  --domains                  Show detailed domain status")
            print("\nDomain Management:")
            print(
                "  --test-domain <sub.domain> Create test subdomain (e.g., test.smartwave.co.za)"
            )
            print("  --check-domain <sub.domain> Check subdomain availability")
            print("\nLegacy commands:")
            print("  deploy <domain> <port> [type]    Deploy domain")
            print("  remove <domain>                  Remove domain")
            print("  list                             List domains")
            print("\nAPI Endpoints for domain management:")
            print(
                "  GET    /api/domains                           List available domains"
            )
            print(
                "  POST   /api/domains/<domain>/subdomains/check Check subdomain availability"
            )
            print(
                "  POST   /api/deploy/nodejs-domain              Deploy with domain setup"
            )
            print("  GET    /api/domains/subdomains                List all subdomains")
            print("  DELETE /api/domains/subdomains/<domain>       Delete subdomain")

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
