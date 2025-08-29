#!/bin/bash
# simple-deploy.sh - Direct deployment script

set -e

# Configuration
REMOTE_HOST="75.119.141.162"
REMOTE_USER="root"
REMOTE_PATH="/opt/hosting-manager"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[DEPLOY]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

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

# Stop any existing services
systemctl stop hosting-api 2>/dev/null || true
systemctl stop hosting-manager 2>/dev/null || true
pkill -f "hosting.*api" || true
pkill -f "simple-hosting" || true

# Create directory structure
mkdir -p /opt/hosting-manager
cd /opt/hosting-manager

# Extract files
tar -xzf /tmp/hosting-manager.tar.gz

# Create requirements.txt if it doesn't exist
if [ ! -f "requirements.txt" ]; then
    cat > requirements.txt << 'EOF'
flask>=2.3.0
flask-cors>=4.0.0
gunicorn>=20.1.0
psutil>=5.9.0
requests>=2.31.0
EOF
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Install PM2 if not present
if ! command -v pm2 &> /dev/null; then
    echo "Installing PM2..."
    npm install -g pm2 || echo "PM2 install failed, continuing without it"
fi

# Create __init__.py files if missing
touch src/__init__.py
touch src/api/__init__.py
touch src/core/__init__.py
touch src/monitoring/__init__.py
touch src/utils/__init__.py

# Set permissions
chown -R www-data:www-data /opt/hosting-manager
chmod +x hosting_manager.py

# Create systemd service
cat > /etc/systemd/system/hosting-manager.service << 'EOF'
[Unit]
Description=Hosting Manager v3.0
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
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Run initial setup
echo "Running system setup..."
python3 hosting_manager.py --setup

# Start and enable service
systemctl enable hosting-manager
systemctl start hosting-manager

# Cleanup
rm -f /tmp/hosting-manager.tar.gz

echo "Deployment completed!"
REMOTE_SCRIPT

# Cleanup local package
rm hosting-manager.tar.gz

# Wait a moment for service to start
sleep 3

# Health check
print_status "Running health check..."
if ssh "${REMOTE_USER}@${REMOTE_HOST}" "curl -s http://localhost:5000/api/health" > /dev/null; then
    print_success "Health check passed!"
    print_success "Service is running at http://$REMOTE_HOST:5000"
    
    # Test the problematic endpoint
    print_status "Testing /api/processes endpoint..."
    if ssh "${REMOTE_USER}@${REMOTE_HOST}" "curl -s http://localhost:5000/api/processes" | grep -q "success"; then
        print_success "/api/processes endpoint is working!"
    else
        print_error "/api/processes endpoint may have issues"
    fi
else
    print_error "Health check failed"
    print_status "Checking service status..."
    ssh "${REMOTE_USER}@${REMOTE_HOST}" "systemctl status hosting-manager --no-pager -l"
fi