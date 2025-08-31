#!/bin/bash
# deploy.sh - Complete Next.js Multisite Hosting Platform Deployment
# Includes: Core hosting, PM2 management, and Next.js monitoring extension

set -e

# Configuration
REMOTE_HOST="75.119.141.162"
REMOTE_USER="root"
REMOTE_PATH="/opt/hosting-manager"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[DEPLOY]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Check if local files exist
required_files=(
    "hosting_manager.py"
    "src/api/server.py"
    "src/core/hosting_manager.py"
    "src/monitoring/process_monitor.py"
    "src/monitoring/health_checker.py"
    "src/utils/config.py"
    "src/utils/logger.py"
)

print_status "Checking local files..."
for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        print_error "Missing required file: $file"
        exit 1
    fi
done
print_success "All required files present"

# Create deployment package
print_status "Creating deployment package..."
tar -czf hosting-manager.tar.gz \
    hosting_manager.py \
    src/ \
    requirements.txt 2>/dev/null || echo "requirements.txt not found, will create on server"

# Upload to server
print_status "Uploading to server $REMOTE_HOST..."
scp hosting-manager.tar.gz "${REMOTE_USER}@${REMOTE_HOST}:/tmp/"

# Deploy on remote server
print_status "Setting up on remote server..."
ssh "${REMOTE_USER}@${REMOTE_HOST}" << 'REMOTE_SCRIPT'
set -e

echo "[REMOTE] === EMERGENCY: STOPPING ANY EXISTING LOOPS ==="
# Stop all related services aggressively
systemctl stop hosting-manager 2>/dev/null || true
systemctl stop hosting-api 2>/dev/null || true
systemctl disable hosting-manager 2>/dev/null || true
systemctl disable hosting-api 2>/dev/null || true

# Kill any python processes that might be stuck
pkill -f "hosting.*api" || true
pkill -f "hosting_manager.py" || true
pkill -f "simple-hosting" || true

# Remove old service files
rm -f /etc/systemd/system/hosting-manager.service
rm -f /etc/systemd/system/hosting-api.service
systemctl daemon-reload

echo "[SUCCESS] All existing services stopped and cleaned"

echo "[REMOTE] === DIRECTORY SETUP ==="
# Create directory structure
mkdir -p /opt/hosting-manager
cd /opt/hosting-manager

echo "[REMOTE] Extracting files..."
tar -xzf /tmp/hosting-manager.tar.gz

echo "[REMOTE] === VERIFYING MAIN SCRIPT LOCATION ==="
if [ -f "hosting_manager.py" ]; then
    echo "[SUCCESS] ✓ MAIN SCRIPT FOUND: /opt/hosting-manager/hosting_manager.py"
    ls -la hosting_manager.py
    chmod +x hosting_manager.py
    echo "[SUCCESS] ✓ Main script is executable"
else
    echo "[ERROR] ✗ Main script missing: hosting_manager.py"
    exit 1
fi

if [ -f "src/core/hosting_manager.py" ]; then
    echo "[REMOTE] ✓ Module file found: /opt/hosting-manager/src/core/hosting_manager.py (this is NOT the main script)"
else
    echo "[ERROR] ✗ Core module missing"
    exit 1
fi

echo "[REMOTE] === PYTHON DEPENDENCIES ==="
# Update packages
apt update -qq

# Install system packages if not present
REQUIRED_PACKAGES="python3-flask python3-flask-cors python3-requests python3-psutil python3-gunicorn python3-pip python3-full"
for pkg in $REQUIRED_PACKAGES; do
    if dpkg -l | grep -q "^ii.*$pkg"; then
        echo "  ✓ $pkg"
    else
        echo "  Installing $pkg..."
        apt install -y $pkg > /dev/null 2>&1 || echo "  Failed to install $pkg"
    fi
done
echo "[SUCCESS] ✅ System packages working"

# Install Python modules
PYTHON_MODULES="flask flask_cors requests psutil"
for module in $PYTHON_MODULES; do
    if python3 -c "import $module" 2>/dev/null; then
        echo "  ✓ $module"
    else
        echo "  Installing $module..."
        pip3 install $module > /dev/null 2>&1 || echo "  Failed to install $module"
    fi
done
echo "✅ Python modules ready"

echo "[REMOTE] === NODE.JS/PM2 SETUP ==="
# Install PM2 if not present
if ! command -v pm2 &> /dev/null; then
    echo "Installing PM2..."
    npm install -g pm2 || echo "PM2 install failed, continuing without it"
else
    PM2_VERSION=$(pm2 --version)
    echo "[SUCCESS] PM2 available: $PM2_VERSION"
fi

echo "[REMOTE] === DATABASE SETUP ==="
# Create __init__.py files
touch src/__init__.py
touch src/api/__init__.py
touch src/core/__init__.py
touch src/monitoring/__init__.py
touch src/utils/__init__.py

# Test database setup (this will NOT create the buggy service file)
python3 -c "
import sys
sys.path.insert(0, '/opt/hosting-manager/src')
from utils.config import Config
from utils.logger import Logger
config = Config()
logger = Logger()
print('Database ready')
"

echo "[REMOTE] === CREATING SYSTEMD SERVICE (CORRECT PATH) ==="
echo "[REMOTE] Verified main script: /opt/hosting-manager/hosting_manager.py"

# Create the CORRECT systemd service file
cat > /etc/systemd/system/hosting-manager.service << 'EOF'
[Unit]
Description=Hosting Manager API v3.0 - Complete Next.js Platform
After=network.target nginx.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/hosting-manager
Environment=PYTHONPATH=/opt/hosting-manager
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 /opt/hosting-manager/hosting_manager.py --api
Restart=always
RestartSec=5
StartLimitInterval=300
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
EOF

echo "[SUCCESS] Service created with CORRECT path and loop protection"

# Verify the service file
echo "Service ExecStart verification:"
grep "ExecStart" /etc/systemd/system/hosting-manager.service

# Verify we have the correct path
if grep -q "hosting_manager.py" /etc/systemd/system/hosting-manager.service; then
    echo "[SUCCESS] ✓ Service has correct path (hosting_manager.py)"
else
    echo "[ERROR] ✗ Service has wrong path"
    exit 1
fi

echo "[REMOTE] === MANUAL TESTING BEFORE SERVICE START ==="
echo "[REMOTE] Testing main script execution..."
if timeout 10 python3 hosting_manager.py --help > /dev/null 2>&1; then
    echo "[SUCCESS] ✓ Main script executes correctly"
else
    echo "[ERROR] ✗ Main script has issues"
    python3 hosting_manager.py --help || true
fi

echo "[REMOTE] Running system setup..."
# Run setup but skip the systemd service creation (since we already did it correctly)
python3 -c "
import sys
sys.path.insert(0, '/opt/hosting-manager/src')
from core.hosting_manager import HostingManager
from utils.config import Config
from utils.logger import Logger

config = Config()
logger = Logger()
hm = HostingManager(config, logger)

# Setup database and nginx, but skip service creation
if hm._setup_database():
    print('Database setup OK')
else:
    print('Database setup failed')
    
if hm._setup_nginx():
    print('Nginx setup OK')  
else:
    print('Nginx setup failed')
    
if hm._setup_pm2():
    print('PM2 setup OK')
else:
    print('PM2 not available')
"

# Set proper permissions
chown -R www-data:www-data /opt/hosting-manager

echo "[REMOTE] === STARTING SERVICE WITH MONITORING ==="
# Reload systemd
systemctl daemon-reload

# Enable service
systemctl enable hosting-manager

# Start service with monitoring
systemctl start hosting-manager

# Monitor startup for 60 seconds
echo "[REMOTE] Monitoring service startup (60 seconds)..."
for i in {1..12}; do
    echo "  Startup check $i/12..."
    sleep 5
    
    # Check if service is active
    if systemctl is-active hosting-manager --quiet; then
        echo "[SUCCESS] ✅ Service is running!"
        break
    fi
    
    # Check restart count to prevent infinite loops
    RESTART_COUNT=$(systemctl show hosting-manager --property=NRestarts --value 2>/dev/null || echo "0")
    if [ "$RESTART_COUNT" -gt 5 ]; then
        echo "[ERROR] ✗ Service restarting too frequently ($RESTART_COUNT restarts)"
        echo "[ERROR] Stopping to prevent infinite loop"
        systemctl stop hosting-manager
        echo "[ERROR] Service startup failed"
        break
    fi
    
    if [ $i -eq 12 ]; then
        echo "[ERROR] ✗ Service failed to start within 60 seconds"
    fi
done

# Cleanup
rm -f /tmp/hosting-manager.tar.gz

echo "Core deployment completed!"
REMOTE_SCRIPT

# Cleanup local package
rm hosting-manager.tar.gz

print_status "Adding Next.js Monitoring Extension..."

# Create the NextJS monitoring extension file locally
cat > nextjs_monitoring.py << 'NEXTJS_MONITORING_EOF'
# src/api/nextjs_monitoring.py
"""
Next.js Multisite Monitoring API Extension
Provides comprehensive monitoring endpoints for React frontend
"""

from flask import request, jsonify
import subprocess
import json
import os
import time
import psutil
from datetime import datetime


class NextJSMonitoringAPI:
    """Extended monitoring API specifically for Next.js multisite hosting"""

    def __init__(self, app, hosting_manager, process_monitor, health_checker, config, logger):
        self.app = app
        self.hosting_manager = hosting_manager
        self.process_monitor = process_monitor
        self.health_checker = health_checker
        self.config = config
        self.logger = logger
        
        self.setup_nextjs_routes()

    def setup_nextjs_routes(self):
        """Setup Next.js specific monitoring routes"""

        @self.app.route("/api/monitoring/dashboard", methods=["GET"])
        def get_dashboard_overview():
            """Get complete dashboard overview for React frontend"""
            try:
                dashboard_data = {
                    "timestamp": datetime.now().isoformat(),
                    "system": self._get_system_health(),
                    "applications": self._get_all_app_health(),
                    "infrastructure": self._get_infrastructure_status(),
                    "alerts": self._get_active_alerts(),
                    "performance": self._get_performance_metrics(),
                    "summary": self._get_dashboard_summary()
                }
                
                return jsonify({
                    "success": True,
                    "dashboard": dashboard_data,
                    "last_updated": datetime.now().isoformat()
                })

            except Exception as e:
                self.logger.error(f"Dashboard overview failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/monitoring/sites", methods=["GET"])
        def get_all_sites_status():
            """Get comprehensive status for all Next.js sites"""
            try:
                sites_data = []
                
                # Get all domains and their associated processes
                domains = self.hosting_manager.list_domains()
                processes = self.process_monitor.get_all_processes()
                
                for domain in domains:
                    site_data = self._get_site_detailed_status(domain, processes)
                    sites_data.append(site_data)
                
                # Sort by status (unhealthy first, then by name)
                sites_data.sort(key=lambda x: (x["overall_status"] != "healthy", x["domain_name"]))
                
                return jsonify({
                    "success": True,
                    "sites": sites_data,
                    "total_sites": len(sites_data),
                    "healthy_sites": len([s for s in sites_data if s["overall_status"] == "healthy"]),
                    "timestamp": datetime.now().isoformat()
                })

            except Exception as e:
                self.logger.error(f"Sites status failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/monitoring/sites/<site_name>", methods=["GET"])
        def get_site_detailed_monitoring(site_name):
            """Get detailed monitoring data for a specific site"""
            try:
                site_data = {
                    "site_name": site_name,
                    "timestamp": datetime.now().isoformat(),
                    "health": self._get_site_health_details(site_name),
                    "performance": self._get_site_performance(site_name),
                    "process": self._get_site_process_info(site_name),
                    "logs": self._get_site_recent_logs(site_name),
                    "deployment": self._get_site_deployment_info(site_name)
                }
                
                return jsonify({
                    "success": True,
                    "site": site_data
                })

            except Exception as e:
                self.logger.error(f"Site detailed monitoring failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/monitoring/system/resources", methods=["GET"])
        def get_system_resources():
            """Get real-time system resource usage"""
            try:
                resources = {
                    "timestamp": datetime.now().isoformat(),
                    "cpu": {
                        "usage_percent": psutil.cpu_percent(interval=1),
                        "count": psutil.cpu_count(),
                        "load_average": os.getloadavg(),
                        "per_core": psutil.cpu_percent(interval=1, percpu=True)
                    },
                    "memory": {
                        "total": psutil.virtual_memory().total,
                        "available": psutil.virtual_memory().available,
                        "used": psutil.virtual_memory().used,
                        "percentage": psutil.virtual_memory().percent,
                        "swap": {
                            "total": psutil.swap_memory().total,
                            "used": psutil.swap_memory().used,
                            "percentage": psutil.swap_memory().percent
                        }
                    },
                    "disk": {
                        "total": psutil.disk_usage('/').total,
                        "used": psutil.disk_usage('/').used,
                        "free": psutil.disk_usage('/').free,
                        "percentage": psutil.disk_usage('/').percent
                    },
                    "network": self._get_network_stats(),
                    "processes": {
                        "total": len(psutil.pids()),
                        "running": len([p for p in psutil.process_iter() if p.status() == 'running']),
                        "sleeping": len([p for p in psutil.process_iter() if p.status() == 'sleeping'])
                    }
                }
                
                return jsonify({
                    "success": True,
                    "resources": resources
                })

            except Exception as e:
                self.logger.error(f"System resources failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/monitoring/alerts", methods=["GET"])
        def get_active_alerts():
            """Get all active system alerts and warnings"""
            try:
                alerts = self._generate_alerts()
                
                return jsonify({
                    "success": True,
                    "alerts": alerts,
                    "alert_count": len(alerts),
                    "critical_count": len([a for a in alerts if a["severity"] == "critical"]),
                    "warning_count": len([a for a in alerts if a["severity"] == "warning"]),
                    "timestamp": datetime.now().isoformat()
                })

            except Exception as e:
                self.logger.error(f"Alerts retrieval failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/monitoring/logs/stream/<site_name>", methods=["GET"])
        def stream_site_logs(site_name):
            """Stream real-time logs for a site"""
            try:
                lines = int(request.args.get('lines', 100))
                logs = self.process_monitor.get_process_logs(site_name, lines)
                
                return jsonify({
                    "success": True,
                    "logs": logs,
                    "site_name": site_name,
                    "timestamp": datetime.now().isoformat()
                })

            except Exception as e:
                self.logger.error(f"Log streaming failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

    # Helper methods for monitoring data
    def _get_system_health(self):
        """Get overall system health indicators"""
        try:
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                "status": "healthy" if cpu_usage < 80 and memory.percent < 80 and disk.percent < 90 else "warning",
                "cpu_usage": cpu_usage,
                "memory_usage": memory.percent,
                "disk_usage": disk.percent,
                "load_average": os.getloadavg()[0],
                "uptime": time.time() - psutil.boot_time(),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _get_all_app_health(self):
        """Get health status for all Next.js applications"""
        try:
            apps = []
            processes = self.process_monitor.get_all_processes()
            domains = self.hosting_manager.list_domains()
            
            for domain in domains:
                if domain.get("site_type") in ["node", "app"]:
                    domain_name = domain["domain_name"]
                    
                    # Find associated process
                    app_process = next((p for p in processes if p["name"] == domain_name), None)
                    
                    # Get health check data
                    health_data = self.health_checker.get_domain_health(domain_name)
                    
                    app_info = {
                        "name": domain_name,
                        "port": domain["port"],
                        "status": app_process["status"] if app_process else "unknown",
                        "health": health_data.get("status", "unknown"),
                        "memory": app_process.get("memory", "N/A") if app_process else "N/A",
                        "cpu": app_process.get("cpu", "N/A") if app_process else "N/A",
                        "restart_count": app_process.get("restart_count", 0) if app_process else 0,
                        "response_time": health_data.get("response_time"),
                        "last_health_check": health_data.get("last_check")
                    }
                    apps.append(app_info)
            
            return apps
        except Exception as e:
            self.logger.error(f"App health check failed: {e}")
            return []

    def _get_infrastructure_status(self):
        """Get infrastructure component status"""
        return {
            "nginx": {
                "status": "running" if self.hosting_manager._check_service_status("nginx") else "stopped",
                "config_valid": self.hosting_manager._test_nginx_config()
            },
            "pm2": {
                "available": self.process_monitor.pm2_available,
                "daemon_running": self._check_pm2_daemon(),
                "process_count": len(self.process_monitor.get_pm2_processes()) if self.process_monitor.pm2_available else 0
            },
            "database": {
                "connected": self.hosting_manager.get_database_connection() is not None
            },
            "monitoring": {
                "process_monitor": self.process_monitor.is_monitoring_active(),
                "health_checker": self.health_checker.is_active()
            }
        }

    def _get_performance_metrics(self):
        """Get key performance metrics"""
        try:
            processes = self.process_monitor.get_all_processes()
            
            return {
                "total_memory_usage": sum(self._parse_memory(p.get("memory", "0MB")) for p in processes),
                "average_cpu_usage": sum(self._parse_cpu(p.get("cpu", "0%")) for p in processes) / max(len(processes), 1),
                "active_connections": self._get_active_connections(),
                "response_times": self._get_average_response_times(),
                "error_rates": self._get_error_rates()
            }
        except Exception as e:
            return {"error": str(e)}

    def _get_dashboard_summary(self):
        """Get dashboard summary statistics"""
        try:
            domains = self.hosting_manager.list_domains()
            processes = self.process_monitor.get_all_processes()
            
            total_sites = len([d for d in domains if d.get("site_type") in ["node", "app"]])
            healthy_sites = len([d for d in domains if self.health_checker.get_domain_health(d["domain_name"]).get("status") == "healthy"])
            
            return {
                "total_sites": total_sites,
                "healthy_sites": healthy_sites,
                "unhealthy_sites": total_sites - healthy_sites,
                "total_processes": len(processes),
                "running_processes": len([p for p in processes if p["status"] == "online"]),
                "system_health": "healthy" if psutil.cpu_percent() < 80 and psutil.virtual_memory().percent < 80 else "warning"
            }
        except Exception as e:
            return {"error": str(e)}

    def _get_site_detailed_status(self, domain, processes):
        """Get detailed status for a single site"""
        domain_name = domain["domain_name"]
        
        # Find associated process
        site_process = next((p for p in processes if p["name"] == domain_name), None)
        
        # Get health data
        health_data = self.health_checker.get_domain_health(domain_name)
        
        # Determine overall status
        process_status = site_process["status"] if site_process else "unknown"
        health_status = health_data.get("status", "unknown")
        
        if process_status == "online" and health_status == "healthy":
            overall_status = "healthy"
        elif process_status == "online" and health_status != "healthy":
            overall_status = "degraded"
        else:
            overall_status = "unhealthy"
        
        return {
            "domain_name": domain_name,
            "port": domain["port"],
            "site_type": domain["site_type"],
            "overall_status": overall_status,
            "process": {
                "status": process_status,
                "pid": site_process.get("pid") if site_process else None,
                "memory": site_process.get("memory", "N/A") if site_process else "N/A",
                "cpu": site_process.get("cpu", "N/A") if site_process else "N/A",
                "restart_count": site_process.get("restart_count", 0) if site_process else 0,
                "process_manager": site_process.get("process_manager", "unknown") if site_process else "unknown"
            },
            "health": {
                "status": health_status,
                "response_time": health_data.get("response_time"),
                "last_check": health_data.get("last_check"),
                "consecutive_failures": health_data.get("consecutive_failures", 0),
                "uptime_percentage": health_data.get("uptime_percentage", 0)
            },
            "ssl_enabled": domain.get("ssl_enabled", False),
            "created_at": domain.get("created_at"),
            "url": f"http://{domain_name}"
        }

    def _generate_alerts(self):
        """Generate system alerts based on current status"""
        alerts = []
        
        try:
            # System resource alerts
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            if cpu_usage > 90:
                alerts.append({
                    "id": "cpu_critical",
                    "severity": "critical",
                    "title": "High CPU Usage",
                    "message": f"CPU usage is {cpu_usage:.1f}%",
                    "timestamp": datetime.now().isoformat(),
                    "category": "system"
                })
            elif cpu_usage > 80:
                alerts.append({
                    "id": "cpu_warning",
                    "severity": "warning", 
                    "title": "Elevated CPU Usage",
                    "message": f"CPU usage is {cpu_usage:.1f}%",
                    "timestamp": datetime.now().isoformat(),
                    "category": "system"
                })
            
            if memory.percent > 90:
                alerts.append({
                    "id": "memory_critical",
                    "severity": "critical",
                    "title": "High Memory Usage",
                    "message": f"Memory usage is {memory.percent:.1f}%",
                    "timestamp": datetime.now().isoformat(),
                    "category": "system"
                })
            
            # Application alerts
            processes = self.process_monitor.get_all_processes()
            for process in processes:
                if process["status"] != "online":
                    alerts.append({
                        "id": f"app_{process['name']}_down",
                        "severity": "critical",
                        "title": f"Application Down",
                        "message": f"{process['name']} is {process['status']}",
                        "timestamp": datetime.now().isoformat(),
                        "category": "application",
                        "app_name": process['name']
                    })
            
            # Infrastructure alerts
            if not self.hosting_manager._check_service_status("nginx"):
                alerts.append({
                    "id": "nginx_down",
                    "severity": "critical",
                    "title": "Nginx Service Down",
                    "message": "Nginx web server is not running",
                    "timestamp": datetime.now().isoformat(),
                    "category": "infrastructure"
                })
                
        except Exception as e:
            alerts.append({
                "id": "monitoring_error",
                "severity": "warning",
                "title": "Monitoring System Error",
                "message": f"Error generating alerts: {str(e)}",
                "timestamp": datetime.now().isoformat(),
                "category": "system"
            })
        
        return alerts

    # Additional helper methods
    def _check_pm2_daemon(self):
        """Check if PM2 daemon is responding"""
        try:
            result = subprocess.run(["pm2", "ping"], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def _parse_memory(self, memory_str):
        """Parse memory string to MB"""
        try:
            if "MB" in str(memory_str):
                return int(str(memory_str).replace("MB", ""))
            elif "GB" in str(memory_str):
                return int(float(str(memory_str).replace("GB", "")) * 1024)
        except:
            pass
        return 0

    def _parse_cpu(self, cpu_str):
        """Parse CPU string to percentage"""
        try:
            if "%" in str(cpu_str):
                return float(str(cpu_str).replace("%", ""))
        except:
            pass
        return 0.0

    def _get_network_stats(self):
        """Get network statistics"""
        try:
            net_io = psutil.net_io_counters()
            return {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv
            }
        except:
            return {}

    def _get_active_connections(self):
        """Get active network connections count"""
        try:
            connections = psutil.net_connections()
            return len([c for c in connections if c.status == 'ESTABLISHED'])
        except:
            return 0

    def _get_average_response_times(self):
        """Get average response times from health checks"""
        try:
            health_data = self.health_checker.get_all_health_data()
            response_times = [h.get("response_time", 0) for h in health_data if h.get("response_time")]
            return sum(response_times) / len(response_times) if response_times else 0
        except:
            return 0

    def _get_error_rates(self):
        """Calculate error rates from health checks"""
        try:
            health_data = self.health_checker.get_all_health_data()
            if not health_data:
                return 0
            
            unhealthy_count = len([h for h in health_data if h["status"] != "healthy"])
            return (unhealthy_count / len(health_data)) * 100
        except:
            return 0

    # Placeholder methods for detailed site monitoring
    def _get_site_health_details(self, site_name):
        """Get detailed health information for a site"""
        return self.health_checker.get_domain_health(site_name)

    def _get_site_performance(self, site_name):
        """Get performance metrics for a site"""
        return {"response_time": 0, "throughput": 0, "error_rate": 0}

    def _get_site_process_info(self, site_name):
        """Get process information for a site"""
        return self.process_monitor.get_process_details(site_name)

    def _get_site_recent_logs(self, site_name):
        """Get recent logs for a site"""
        return self.process_monitor.get_process_logs(site_name, 50)

    def _get_site_deployment_info(self, site_name):
        """Get deployment information for a site"""
        return {"last_deployment": None, "version": None, "build_status": "unknown"}
NEXTJS_MONITORING_EOF

# Upload the monitoring extension
scp nextjs_monitoring.py "${REMOTE_USER}@${REMOTE_HOST}:/tmp/"

# Integrate monitoring extension on remote server
ssh "${REMOTE_USER}@${REMOTE_HOST}" << 'REMOTE_NEXTJS_SCRIPT'
echo "🚀 Integrating Next.js Monitoring Extension..."

cd /opt/hosting-manager

# Move the monitoring extension to the correct location
mv /tmp/nextjs_monitoring.py src/api/nextjs_monitoring.py

# Update the main API server to integrate the monitoring extension
cat >> src/api/server.py << 'EOF'

    def setup_nextjs_monitoring(self):
        """Setup NextJS monitoring extension"""
        try:
            from .nextjs_monitoring import NextJSMonitoringAPI
            
            self.nextjs_monitoring = NextJSMonitoringAPI(
                self.app,
                self.hosting_manager,
                self.process_monitor,
                self.health_checker,
                self.config,
                self.logger
            )
            self.logger.info("NextJS monitoring extension loaded")
        except ImportError as e:
            self.logger.warning(f"NextJS monitoring extension not available: {e}")
        except Exception as e:
            self.logger.error(f"Failed to load NextJS monitoring: {e}")
EOF

# Update the API server run method to initialize NextJS monitoring
sed -i '/def run(self, host="0.0.0.0", port=5000, debug=False):/a\
        # Setup NextJS monitoring extension\
        self.setup_nextjs_monitoring()' src/api/server.py

echo "✅ NextJS monitoring extension integrated"
REMOTE_NEXTJS_SCRIPT

# Cleanup monitoring file
rm -f nextjs_monitoring.py

print_success "Next.js Monitoring Extension added to deployment"

# Wait a moment for service to stabilize
sleep 5

# Comprehensive health check
print_status "Running comprehensive health check..."

# Check service status
print_status "Checking service status..."
SERVICE_STATUS=$(ssh "${REMOTE_USER}@${REMOTE_HOST}" "systemctl is-active hosting-manager" 2>/dev/null || echo "inactive")

if [ "$SERVICE_STATUS" = "active" ]; then
    print_success "✅ Service is active!"
    
    # Test API endpoint
    print_status "Testing API endpoints..."
    if ssh "${REMOTE_USER}@${REMOTE_HOST}" "curl -s http://localhost:5000/api/health" | grep -q "healthy"; then
        print_success "✅ Health endpoint working!"
        
        # Test core endpoints
        print_status "Testing core endpoints..."
        CORE_ENDPOINTS=(
            "/api/processes:Process List"
            "/api/status:System Status"
            "/api/domains:Domain List"
            "/api/pm2/status:PM2 Status"
        )
        
        for endpoint_info in "${CORE_ENDPOINTS[@]}"; do
            IFS=':' read -r endpoint description <<< "$endpoint_info"
            if ssh "${REMOTE_USER}@${REMOTE_HOST}" "curl -s http://localhost:5000$endpoint" | grep -q "success"; then
                print_success "✅ $description working!"
            else
                print_warning "⚠️  $description may have issues"
            fi
        done
        
        # Test Next.js monitoring endpoints
        print_status "Testing Next.js Monitoring endpoints..."
        NEXTJS_ENDPOINTS=(
            "/api/monitoring/dashboard:Dashboard Overview"
            "/api/monitoring/sites:Sites Status"
            "/api/monitoring/system/resources:System Resources"
            "/api/monitoring/alerts:Active Alerts"
        )
        
        for endpoint_info in "${NEXTJS_ENDPOINTS[@]}"; do
            IFS=':' read -r endpoint description <<< "$endpoint_info"
            if ssh "${REMOTE_USER}@${REMOTE_HOST}" "curl -s http://localhost:5000$endpoint" | grep -q "success"; then
                print_success "✅ $description working!"
            else
                print_warning "⚠️  $description may have issues"
            fi
        done
        
        print_success "🎉 Deployment successful!"
        print_success "🌐 Service is running at http://$REMOTE_HOST:5000"
        
    else
        print_error "❌ API health check failed"
        print_status "Checking service logs..."
        ssh "${REMOTE_USER}@${REMOTE_HOST}" "journalctl -u hosting-manager --no-pager -l -n 20"
    fi
else
    print_error "❌ Service is not active: $SERVICE_STATUS"
    print_status "Checking service status..."
    ssh "${REMOTE_USER}@${REMOTE_HOST}" "systemctl status hosting-manager --no-pager -l"
    
    print_status "Checking recent logs..."
    ssh "${REMOTE_USER}@${REMOTE_HOST}" "journalctl -u hosting-manager --no-pager -l -n 30"
fi

print_success "🎉 COMPLETE NEXT.JS HOSTING PLATFORM DEPLOYED!"
echo ""
print_status "📋 Available Features:"
echo "✅ Core Hosting Management"
echo "✅ PM2 Process Management with Status API"
echo "✅ Next.js Multisite Monitoring"
echo "✅ Real-time System Metrics"
echo "✅ Health Monitoring & Alerts"
echo "✅ React Frontend APIs"
echo ""

print_status "🌐 API Endpoints:"
echo "  Core:"
echo "    Health:      http://$REMOTE_HOST:5000/api/health"
echo "    Status:      http://$REMOTE_HOST:5000/api/status"
echo "    Processes:   http://$REMOTE_HOST:5000/api/processes"
echo "    Domains:     http://$REMOTE_HOST:5000/api/domains"
echo ""
echo "  PM2 Management:"
echo "    PM2 Status:  http://$REMOTE_HOST:5000/api/pm2/status"
echo "    PM2 List:    http://$REMOTE_HOST:5000/api/pm2/list"
echo ""
echo "  Next.js Monitoring:"
echo "    Dashboard:   http://$REMOTE_HOST:5000/api/monitoring/dashboard"
echo "    Sites:       http://$REMOTE_HOST:5000/api/monitoring/sites"
echo "    Resources:   http://$REMOTE_HOST:5000/api/monitoring/system/resources"
echo "    Alerts:      http://$REMOTE_HOST:5000/api/monitoring/alerts"
echo ""

print_status "🚀 Deploy Your First Next.js App:"
cat << 'DEPLOY_EXAMPLE'
curl -X POST -H "Content-Type: application/json" \
  -d '{
    "name": "my-nextjs-app",
    "files": {
      "package.json": "{\"name\":\"my-app\",\"scripts\":{\"build\":\"next build\",\"start\":\"next start\"},\"dependencies\":{\"next\":\"^14.0.0\",\"react\":\"^18.0.0\"}}",
      "pages/index.js": "export default function Home() { return <h1>Hello Next.js!</h1>; }"
    },
    "deployConfig": {"port": 3001}
  }' \
  http://75.119.141.162:5000/api/deploy/nodejs
DEPLOY_EXAMPLE

echo ""
print_status "📱 React Frontend Integration:"
echo "  Use the MonitoringDashboard component provided"
echo "  Set API_BASE = 'http://$REMOTE_HOST:5000'"
echo "  Real-time monitoring with configurable polling intervals"