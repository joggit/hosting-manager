#!/bin/bash
# deploy-with-modular-api.sh - Deployment script that preserves the modular API structure

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

print_status "=== Hosting Manager v3.0 - Modular API Deployment ==="

# Check if we're in the right directory
if [ ! -d "src" ]; then
    print_error "Please run this script from the hosting-manager root directory"
    exit 1
fi

# Check if required source files exist
required_files=(
    "src/core/hosting_manager.py"
    "src/monitoring/process_monitor.py"
    "src/monitoring/health_checker.py"
    "src/utils/config.py"
    "src/utils/logger.py"
    "src/api/app.py"
    "src/api/routes/__init__.py"
    "hosting_manager.py"
)

print_status "Checking required files..."
for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        print_error "Missing required file: $file"
        exit 1
    fi
done
print_success "All required files present"

# Check for modular API routes
route_count=$(find src/api/routes -name "*.py" -not -name "__init__.py" | wc -l)
service_count=$(find src/api/services -name "*.py" -not -name "__init__.py" 2>/dev/null | wc -l || echo 0)

print_status "Found $route_count route modules and $service_count service modules"

# Create deployment directory
print_status "Preparing deployment files..."
rm -rf deploy-temp
mkdir -p deploy-temp

# Copy ALL source files as-is (preserve your modular structure)
cp -r src/ deploy-temp/
cp hosting_manager.py deploy-temp/

# Ensure the hosting_manager.py imports from api.app (not hardcoded inline Flask)
if grep -q "from api.app import HostingAPI" deploy-temp/hosting_manager.py; then
    print_success "hosting_manager.py correctly imports modular API"
else
    print_warning "hosting_manager.py may not be using modular API - checking..."
    
    # If it doesn't import api.app, fix it
    if ! grep -q "from api.app import" deploy-temp/hosting_manager.py; then
        print_status "Fixing hosting_manager.py to use modular API..."
        sed -i 's/from api.server import HostingAPI/from api.app import HostingAPI/' deploy-temp/hosting_manager.py 2>/dev/null || true
        
        # Make sure there's an import for api.app somewhere
        if ! grep -q "from api.app import HostingAPI" deploy-temp/hosting_manager.py; then
            # Add the import after other imports
            sed -i '/from utils.logger import Logger/a from api.app import HostingAPI' deploy-temp/hosting_manager.py
        fi
    fi
fi

# Create requirements.txt with all needed dependencies
cat > deploy-temp/requirements.txt << 'EOF'
flask>=2.3.0
flask-cors>=4.0.0
gunicorn>=20.1.0
psutil>=5.9.0
requests>=2.31.0
sqlite3
EOF

# Create all necessary __init__.py files for proper imports
print_status "Creating package structure..."
touch deploy-temp/src/__init__.py
touch deploy-temp/src/api/__init__.py
touch deploy-temp/src/api/routes/__init__.py
touch deploy-temp/src/api/services/__init__.py
touch deploy-temp/src/core/__init__.py
touch deploy-temp/src/monitoring/__init__.py
touch deploy-temp/src/utils/__init__.py

# Verify the modular API structure is intact
print_status "Verifying modular API structure..."
if [ -f "deploy-temp/src/api/app.py" ] && [ -f "deploy-temp/src/api/routes/__init__.py" ]; then
    print_success "Modular API structure preserved"
else
    print_error "Modular API structure broken"
    exit 1
fi

# Check that api.app has route registration
if grep -q "register_all_routes" deploy-temp/src/api/app.py; then
    print_success "API app includes route registration"
else
    print_error "API app missing route registration - deployment will only have 3 endpoints"
    print_status "Your src/api/app.py needs to call register_all_routes()"
    exit 1
fi

print_success "Deployment files prepared with modular API"

# Create deployment package
print_status "Creating deployment package..."
cd deploy-temp
tar -czf ../hosting-manager-modular.tar.gz .
cd ..

# Upload to server
print_status "Uploading to server $REMOTE_HOST..."
scp hosting-manager-modular.tar.gz "${REMOTE_USER}@${REMOTE_HOST}:/tmp/"

# Deploy on remote server
print_status "Deploying modular API on remote server..."
ssh "${REMOTE_USER}@${REMOTE_HOST}" << 'REMOTE_SCRIPT'
set -e

echo "Stopping existing services..."
systemctl stop hosting-manager 2>/dev/null || true
pkill -f "hosting.*api" || true
pkill -f "hosting_manager" || true

echo "Backing up existing installation..."
if [ -d "/opt/hosting-manager" ]; then
    mv /opt/hosting-manager /opt/hosting-manager.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
fi

echo "Creating directory structure..."
mkdir -p /opt/hosting-manager
cd /opt/hosting-manager

echo "Extracting modular API files..."
tar -xzf /tmp/hosting-manager-modular.tar.gz

echo "Installing Python dependencies..."
pip3 install -r requirements.txt

echo "Setting permissions..."
chown -R www-data:www-data /opt/hosting-manager
chmod +x hosting_manager.py

echo "Testing modular API imports..."
python3 -c "
import sys
sys.path.insert(0, 'src')
try:
    from api.app import HostingAPI
    print('✓ HostingAPI import OK')
    from api.routes import register_all_routes
    print('✓ register_all_routes import OK')
    from api.services import NginxService
    print('✓ Services import OK')
    print('✓ All imports successful - modular API ready')
except Exception as e:
    print(f'✗ Import failed: {e}')
    exit(1)
"

if [ $? -ne 0 ]; then
    echo "Import test failed - aborting deployment"
    exit 1
fi

echo "Creating systemd service for modular API..."
cat > /etc/systemd/system/hosting-manager.service << 'EOF'
[Unit]
Description=Hosting Manager v3.0 - Complete Next.js Platform
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
StartLimitInterval=60
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
EOF

echo "Reloading systemd..."
systemctl daemon-reload

echo "Running system setup..."
python3 hosting_manager.py --setup || echo "Setup had some warnings, continuing..."

echo "Enabling and starting modular API service..."
systemctl enable hosting-manager
systemctl start hosting-manager

echo "Cleanup..."
rm -f /tmp/hosting-manager-modular.tar.gz

echo "Modular API deployment completed!"
REMOTE_SCRIPT

# Cleanup local files
rm hosting-manager-modular.tar.gz
rm -rf deploy-temp

# Wait for service to start
print_status "Waiting for modular API service to start..."
sleep 8

# Health check
print_status "Running comprehensive health check..."
if ssh "${REMOTE_USER}@${REMOTE_HOST}" "curl -s --connect-timeout 10 http://localhost:5000/api/health" | grep -q "healthy"; then
    print_success "Health check passed!"
    print_success "Modular API server is running at http://$REMOTE_HOST:5000"
    
    # Test the startup-info endpoint to verify route registration
    print_status "Testing modular route registration..."
    startup_response=$(ssh "${REMOTE_USER}@${REMOTE_HOST}" "curl -s --connect-timeout 10 http://localhost:5000/api/startup-info" 2>/dev/null)
    if echo "$startup_response" | grep -q "startup_time"; then
        print_success "/api/startup-info endpoint working - route registration successful!"
        
        # Extract route count from startup-info
        route_count=$(echo "$startup_response" | grep -o '"total_api_routes":[0-9]*' | cut -d: -f2 | head -1)
        if [ ! -z "$route_count" ] && [ "$route_count" -gt 10 ]; then
            print_success "Found $route_count API routes - modular system working!"
        else
            print_warning "Only $route_count routes found - some modules may have failed"
        fi
    else
        print_warning "/api/startup-info not available - using basic tests"
    fi
    
    # Test core endpoints
    print_status "Testing core endpoints..."
    for endpoint in "status" "processes" "domains"; do
        if ssh "${REMOTE_USER}@${REMOTE_HOST}" "curl -s --connect-timeout 5 http://localhost:5000/api/$endpoint" | grep -q '"success"'; then
            print_success "/api/$endpoint is working"
        else
            print_warning "/api/$endpoint may have issues"
        fi
    done
    
    # Test modular endpoints
    print_status "Testing modular endpoints..."
    modular_endpoints=("monitoring/dashboard" "monitoring/health" "pm2/list" "nginx/status")
    working_count=0
    
    for endpoint in "${modular_endpoints[@]}"; do
        if ssh "${REMOTE_USER}@${REMOTE_HOST}" "curl -s --connect-timeout 5 http://localhost:5000/api/$endpoint" | grep -q '"success"'; then
            print_success "/api/$endpoint is working"
            ((working_count++))
        else
            print_warning "/api/$endpoint not available"
        fi
    done
    
    if [ $working_count -gt 2 ]; then
        print_success "Modular API deployment successful! $working_count advanced endpoints working"
    else
        print_warning "Modular API partially working - $working_count advanced endpoints available"
    fi
    
else
    print_error "Health check failed - checking service status..."
    ssh "${REMOTE_USER}@${REMOTE_HOST}" "systemctl status hosting-manager --no-pager -l"
    echo ""
    print_status "Checking logs for errors..."
    ssh "${REMOTE_USER}@${REMOTE_HOST}" "journalctl -u hosting-manager --no-pager -n 30"
fi

print_success "Modular API deployment script completed!"
echo ""
echo "Service Information:"
echo "   URL: http://$REMOTE_HOST:5000"
echo "   Status: ssh root@$REMOTE_HOST 'systemctl status hosting-manager'"
echo "   Logs: ssh root@$REMOTE_HOST 'journalctl -u hosting-manager -f'"
echo ""
echo "Test Commands:"
echo "   curl http://$REMOTE_HOST:5000/api/health | jq"
echo "   curl http://$REMOTE_HOST:5000/api/startup-info | jq"
echo "   curl http://$REMOTE_HOST:5000/api/monitoring/dashboard | jq"
echo "   curl http://$REMOTE_HOST:5000/api/domains | jq"
echo "   curl http://$REMOTE_HOST:5000/api/processes | jq"
echo ""
echo "Route Registration Debug:"
echo "   curl http://$REMOTE_HOST:5000/api/_debug/routes/load-status | jq"