#!/bin/bash
# deploy.sh - Modular API Deployment Script
# Updated for the new modular architecture

set -e

# Configuration - Use environment variables or config file
REMOTE_HOST="${DEPLOY_HOST:-75.119.141.162}"
REMOTE_USER="${DEPLOY_USER:-root}"
REMOTE_PATH="${DEPLOY_PATH:-/opt/hosting-manager}"
BACKUP_PATH="${BACKUP_PATH:-/opt/hosting-manager-backup}"

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

# Parse command line arguments
SKIP_BACKUP=false
QUICK_DEPLOY=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-backup)
            SKIP_BACKUP=true
            shift
            ;;
        --quick)
            QUICK_DEPLOY=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --skip-backup    Skip backup creation"
            echo "  --quick          Quick deployment (skip tests)"
            echo "  --dry-run        Show what would be deployed"
            echo "  --help           Show this help"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if local files exist for new modular structure
required_files=(
    "hosting_manager.py"
    "src/api/app.py"
    "src/api/routes/__init__.py"
    "src/api/routes/health.py"
    "src/api/routes/processes.py"
    "src/api/routes/domains.py"
    "src/api/routes/monitoring.py"
    "src/api/routes/next_port_management.py"
    "src/api/routes/pm2.py"
    "src/api/routes/nginx.py"
    "src/api/routes/logs.py"
    "src/api/routes/utils_routes.py"
    "src/api/services/__init__.py"
    "src/api/services/monitoring_service.py"
    "src/api/services/next_port_service.py"
    "src/api/services/alert_service.py"
    "src/api/services/nginx_service.py"
    "src/api/services/nginx_audit_service.py"
    "src/api/utils.py"
    "src/api/validators.py"
    "src/api/middleware.py"
    "src/core/hosting_manager.py"
    "src/monitoring/process_monitor.py"
    "src/monitoring/health_checker.py"
    "src/utils/config.py"
    "src/utils/logger.py"
)

print_status "Checking local files for modular architecture..."
missing_files=()

for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        missing_files+=("$file")
    fi
done

if [ ${#missing_files[@]} -gt 0 ]; then
    print_error "Missing required files:"
    for file in "${missing_files[@]}"; do
        echo "  - $file"
    done
    print_error "Please ensure you have migrated to the modular architecture"
    exit 1
fi

print_success "All required files present"

# Create deployment package
print_status "Creating deployment package..."
if [ "$DRY_RUN" = true ]; then
    print_status "[DRY RUN] Would create deployment package with:"
    for file in "${required_files[@]}"; do
        echo "  - $file"
    done
    exit 0
fi

# Create deployment info file
cat > deployment_info.json << EOF
{
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "version": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
    "architecture": "modular",
    "deployed_by": "$(whoami)",
    "files": $(printf '%s\n' "${required_files[@]}" | jq -R . | jq -s .)
}
EOF

tar -czf hosting-manager.tar.gz \
    hosting_manager.py \
    src/ \
    deployment_info.json \
    requirements.txt 2>/dev/null || echo "requirements.txt not found, will create on server"

# Upload to server
print_status "Uploading to server $REMOTE_HOST..."
scp hosting-manager.tar.gz "${REMOTE_USER}@${REMOTE_HOST}:/tmp/"

# Deploy on remote server
print_status "Deploying modular API architecture..."
ssh "${REMOTE_USER}@${REMOTE_HOST}" bash << REMOTE_SCRIPT
set -e

SKIP_BACKUP="$SKIP_BACKUP"
QUICK_DEPLOY="$QUICK_DEPLOY"
REMOTE_PATH="$REMOTE_PATH"
BACKUP_PATH="$BACKUP_PATH"

echo "[REMOTE] Starting deployment of modular architecture..."

# Stop existing service
echo "[REMOTE] Stopping existing services..."
systemctl stop hosting-manager 2>/dev/null || true
systemctl stop hosting-api 2>/dev/null || true

# Kill any stuck processes
pkill -f "hosting.*api" || true
pkill -f "hosting_manager.py" || true

echo "[SUCCESS] Services stopped"

# Create backup if requested
if [ "\$SKIP_BACKUP" = false ] && [ -d "\$REMOTE_PATH" ]; then
    echo "[REMOTE] Creating backup..."
    rm -rf "\$BACKUP_PATH"
    cp -r "\$REMOTE_PATH" "\$BACKUP_PATH"
    echo "[SUCCESS] Backup created at \$BACKUP_PATH"
fi

# Create directory structure
echo "[REMOTE] Setting up directories..."
mkdir -p "\$REMOTE_PATH"
cd "\$REMOTE_PATH"

# Extract new files
echo "[REMOTE] Extracting modular architecture..."
tar -xzf /tmp/hosting-manager.tar.gz

# Verify modular structure
echo "[REMOTE] Verifying modular structure..."
required_paths=(
    "src/api/app.py"
    "src/api/routes"
    "src/api/services"
    "src/api/utils.py"
    "src/api/validators.py" 
    "src/api/middleware.py"
)

for path in "\${required_paths[@]}"; do
    if [ ! -e "\$path" ]; then
        echo "[ERROR] Missing: \$path"
        exit 1
    fi
done

echo "[SUCCESS] Modular structure verified"

# Check deployment info
if [ -f "deployment_info.json" ]; then
    echo "[REMOTE] Deployment info:"
    cat deployment_info.json | jq -r '
        "Timestamp: " + .timestamp + 
        "\nVersion: " + .version + 
        "\nArchitecture: " + .architecture +
        "\nDeployed by: " + .deployed_by
    ' 2>/dev/null || cat deployment_info.json
fi

# Install system dependencies
echo "[REMOTE] Installing system dependencies..."
apt update -qq

REQUIRED_PACKAGES="python3-flask python3-flask-cors python3-requests python3-psutil python3-gunicorn python3-pip python3-full nginx sqlite3"
for pkg in \$REQUIRED_PACKAGES; do
    if dpkg -l | grep -q "^ii.*\$pkg"; then
        echo "  ✓ \$pkg"
    else
        echo "  Installing \$pkg..."
        apt install -y \$pkg > /dev/null 2>&1 || echo "  Failed to install \$pkg"
    fi
done

# Install Python packages
echo "[REMOTE] Installing Python packages..."
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt > /dev/null 2>&1
else
    # Create requirements.txt for modular architecture
    cat > requirements.txt << 'REQUIREMENTS_EOF'
flask>=2.3.0
flask-cors>=4.0.0
gunicorn>=20.1.0
psutil>=5.9.0
requests>=2.31.0
REQUIREMENTS_EOF
    pip3 install -r requirements.txt > /dev/null 2>&1
fi

# Install PM2
if ! command -v pm2 &> /dev/null; then
    echo "[REMOTE] Installing PM2..."
    npm install -g pm2 || echo "PM2 install failed, continuing without it"
fi

# Create __init__.py files
echo "[REMOTE] Setting up Python modules..."
find src -type d -exec touch {}/__init__.py \;

# Test import of new modular structure
echo "[REMOTE] Testing modular imports..."
python3 -c "
import sys
sys.path.insert(0, '\$REMOTE_PATH/src')
try:
    from api.app import HostingAPI
    from api.utils import APIResponse
    from api.services import MonitoringService
    print('✓ Modular imports successful')
except Exception as e:
    print('✗ Import failed:', e)
    exit(1)
"

# Run system setup
echo "[REMOTE] Running system setup..."
python3 -c "
import sys
sys.path.insert(0, '\$REMOTE_PATH/src')
from core.hosting_manager import HostingManager
from utils.config import Config
from utils.logger import Logger

config = Config()
logger = Logger()
hm = HostingManager(config, logger)

try:
    if hm._setup_database():
        print('✓ Database setup OK')
    else:
        print('✗ Database setup failed')
        
    if hm._setup_nginx():
        print('✓ Nginx setup OK')  
    else:
        print('✗ Nginx setup failed')
        
    if hm._setup_pm2():
        print('✓ PM2 setup OK')
    else:
        print('ⓘ PM2 not available')
except Exception as e:
    print('✗ Setup failed:', e)
    exit(1)
"

# Create systemd service
echo "[REMOTE] Creating systemd service..."
cat > /etc/systemd/system/hosting-manager.service << 'SERVICE_EOF'
[Unit]
Description=Hosting Manager API v3.0 - Modular Architecture
After=network.target nginx.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=REMOTE_PATH_PLACEHOLDER
Environment=PYTHONPATH=REMOTE_PATH_PLACEHOLDER/src
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 REMOTE_PATH_PLACEHOLDER/hosting_manager.py --api
Restart=always
RestartSec=5
StartLimitInterval=300
StartLimitBurst=3
TimeoutStartSec=30

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# Replace placeholder with actual path
sed -i "s|REMOTE_PATH_PLACEHOLDER|\$REMOTE_PATH|g" /etc/systemd/system/hosting-manager.service

# Set permissions
chown -R www-data:www-data "\$REMOTE_PATH"
chmod +x "\$REMOTE_PATH/hosting_manager.py"

# Reload and start service
echo "[REMOTE] Starting service..."
systemctl daemon-reload
systemctl enable hosting-manager

# Quick smoke test before starting service
if [ "\$QUICK_DEPLOY" = false ]; then
    echo "[REMOTE] Running pre-start tests..."
    timeout 10 python3 "\$REMOTE_PATH/hosting_manager.py" --help > /dev/null 2>&1 || {
        echo "[ERROR] Main script test failed"
        exit 1
    }
    echo "✓ Pre-start tests passed"
fi

systemctl start hosting-manager

# Monitor startup
echo "[REMOTE] Monitoring service startup..."
for i in {1..12}; do
    echo "  Startup check \$i/12..."
    sleep 5
    
    if systemctl is-active hosting-manager --quiet; then
        echo "[SUCCESS] Service is running!"
        break
    fi
    
    # Check for restart loops
    RESTART_COUNT=\$(systemctl show hosting-manager --property=NRestarts --value 2>/dev/null || echo "0")
    if [ "\$RESTART_COUNT" -gt 5 ]; then
        echo "[ERROR] Service restarting too frequently (\$RESTART_COUNT restarts)"
        systemctl stop hosting-manager
        echo "[ERROR] Check logs: journalctl -u hosting-manager --no-pager -l"
        exit 1
    fi
    
    if [ \$i -eq 12 ]; then
        echo "[ERROR] Service failed to start within 60 seconds"
        echo "[ERROR] Check logs: journalctl -u hosting-manager --no-pager -l"
        exit 1
    fi
done

# Test API endpoints
echo "[REMOTE] Testing API endpoints..."
sleep 3

# Test core endpoints
ENDPOINTS=(
    "/api/health:Health Check"
    "/api/status:System Status"  
    "/api/processes:Process List"
    "/api/domains:Domain List"
    "/api/monitoring/dashboard:Dashboard"
    "/api/monitoring/sites:Sites Status"
    "/api/monitoring/system/resources:System Resources"
    "/api/monitoring/alerts:Alerts"
)

for endpoint_info in "\${ENDPOINTS[@]}"; do
    IFS=':' read -r endpoint description <<< "\$endpoint_info"
    echo -n "Testing \$description ... "
    
    response=\$(curl -s --max-time 10 "http://localhost:5000\$endpoint" 2>/dev/null || echo "")
    if echo "\$response" | grep -q '"success": true'; then
        echo "✓"
    else
        echo "✗"
        echo "  Error: \$(echo "\$response" | jq -r '.error // "Connection failed"' 2>/dev/null || echo "Unknown error")"
    fi
done

# Cleanup
rm -f /tmp/hosting-manager.tar.gz

echo "[SUCCESS] Modular API deployment completed!"

REMOTE_SCRIPT

# Cleanup local files
rm hosting-manager.tar.gz deployment_info.json

# Final health check
print_status "Running final health check..."
sleep 3

# Test external access
if curl -s --max-time 10 "http://$REMOTE_HOST:5000/api/health" | grep -q "healthy"; then
    print_success "✅ External API access working!"
    
    # Show deployment summary
    echo ""
    print_success "🎉 MODULAR API DEPLOYMENT SUCCESSFUL!"
    echo ""
    print_status "📋 New Architecture Features:"
    echo "  ✅ Modular route structure"
    echo "  ✅ Service layer separation"
    echo "  ✅ Standardized error handling"
    echo "  ✅ Input validation"
    echo "  ✅ Clean dependency injection"
    echo ""
    
    print_status "🌐 API Base URL: http://$REMOTE_HOST:5000"
    print_status "📝 Test endpoints:"
    echo "  curl http://$REMOTE_HOST:5000/api/health"
    echo "  curl http://$REMOTE_HOST:5000/api/monitoring/dashboard"
    echo "  curl http://$REMOTE_HOST:5000/api/processes"
    echo ""
    
    print_status "🔧 Management:"
    echo "  systemctl status hosting-manager"
    echo "  journalctl -u hosting-manager -f"
    echo "  curl http://$REMOTE_HOST:5000/api/monitoring/alerts"
    
else
    print_error "❌ External API access failed"
    print_status "Check service status:"
    ssh "${REMOTE_USER}@${REMOTE_HOST}" "systemctl status hosting-manager --no-pager -l"
    
    print_status "Recent logs:"
    ssh "${REMOTE_USER}@${REMOTE_HOST}" "journalctl -u hosting-manager --no-pager -l -n 20"
    
    print_status "🔄 Rollback available:"
    echo "  ssh $REMOTE_USER@$REMOTE_HOST 'systemctl stop hosting-manager && rm -rf $REMOTE_PATH && mv $BACKUP_PATH $REMOTE_PATH && systemctl start hosting-manager'"
fi