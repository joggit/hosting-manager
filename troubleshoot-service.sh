#!/bin/bash
# troubleshoot-service.sh - Diagnose hosting-manager service startup issues

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }

print_header "HOSTING MANAGER SERVICE TROUBLESHOOTING"

echo "Diagnosing why hosting-manager service is not starting..."

print_header "1. SERVICE STATUS CHECK"

# Check current service status
echo "Service status:"
systemctl status hosting-manager --no-pager -l || true

echo ""
echo "Service enabled status:"
if systemctl is-enabled hosting-manager &>/dev/null; then
    print_success "Service is enabled"
else
    print_warning "Service is not enabled"
    echo "Fix: systemctl enable hosting-manager"
fi

print_header "2. RECENT LOGS ANALYSIS"

echo "Recent service logs (last 50 lines):"
journalctl -u hosting-manager --no-pager -l -n 50

print_header "3. FILE STRUCTURE VERIFICATION"

REMOTE_PATH="/opt/hosting-manager"

echo "Checking file structure..."

# Check main script
if [ -f "$REMOTE_PATH/hosting_manager.py" ]; then
    print_success "Main script exists: $REMOTE_PATH/hosting_manager.py"
    echo "Permissions: $(ls -la $REMOTE_PATH/hosting_manager.py)"
else
    print_error "Main script missing: $REMOTE_PATH/hosting_manager.py"
fi

# Check modular structure
REQUIRED_DIRS=(
    "src"
    "src/api" 
    "src/api/routes"
    "src/api/services"
    "src/core"
    "src/monitoring"
    "src/utils"
)

echo ""
echo "Checking directory structure:"
for dir in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$REMOTE_PATH/$dir" ]; then
        print_success "$dir/ exists"
    else
        print_error "$dir/ missing"
    fi
done

# Check __init__.py files
echo ""
echo "Checking __init__.py files:"
INIT_FILES=(
    "src/__init__.py"
    "src/api/__init__.py"
    "src/api/routes/__init__.py"
    "src/api/services/__init__.py"
    "src/core/__init__.py"
    "src/monitoring/__init__.py" 
    "src/utils/__init__.py"
)

for init_file in "${INIT_FILES[@]}"; do
    if [ -f "$REMOTE_PATH/$init_file" ]; then
        print_success "$init_file exists"
    else
        print_error "$init_file missing"
        echo "Creating missing __init__.py file..."
        touch "$REMOTE_PATH/$init_file"
    fi
done

print_header "4. PYTHON IMPORT TEST"

echo "Testing Python imports from the main directory..."
cd "$REMOTE_PATH"

# Test basic import
echo "Testing basic module structure:"
python3 -c "
import sys
sys.path.insert(0, '/opt/hosting-manager/src')
try:
    print('✅ Python path setup working')
    import utils.config
    print('✅ utils.config import successful')
    import utils.logger  
    print('✅ utils.logger import successful')
    import core.hosting_manager
    print('✅ core.hosting_manager import successful')
except Exception as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
"

# Test modular API imports
echo ""
echo "Testing modular API imports:"
python3 -c "
import sys
sys.path.insert(0, '/opt/hosting-manager/src')
try:
    from api.app import HostingAPI
    print('✅ api.app.HostingAPI import successful')
    from api.utils import APIResponse
    print('✅ api.utils.APIResponse import successful')
except Exception as e:
    print(f'❌ Modular API import error: {e}')
    print('This suggests the modular migration is incomplete')
    sys.exit(1)
"

print_header "5. MAIN SCRIPT EXECUTION TEST"

echo "Testing main script execution..."
cd "$REMOTE_PATH"

# Test help command
echo "Testing --help flag:"
timeout 10 python3 hosting_manager.py --help || echo "Help command failed or timed out"

echo ""
echo "Testing basic script execution:"
timeout 5 python3 -c "
import sys
sys.path.insert(0, '/opt/hosting-manager/src')
exec(open('hosting_manager.py').read())
" 2>&1 | head -10

print_header "6. SYSTEMD SERVICE FILE CHECK"

SERVICE_FILE="/etc/systemd/system/hosting-manager.service"

echo "Checking systemd service file:"
if [ -f "$SERVICE_FILE" ]; then
    print_success "Service file exists: $SERVICE_FILE"
    echo ""
    echo "Service file contents:"
    cat "$SERVICE_FILE"
    
    echo ""
    echo "Validating service file paths:"
    
    # Check WorkingDirectory
    WORKING_DIR=$(grep "WorkingDirectory=" "$SERVICE_FILE" | cut -d= -f2)
    if [ -d "$WORKING_DIR" ]; then
        print_success "WorkingDirectory exists: $WORKING_DIR"
    else
        print_error "WorkingDirectory missing: $WORKING_DIR"
    fi
    
    # Check ExecStart path
    EXEC_START=$(grep "ExecStart=" "$SERVICE_FILE" | cut -d= -f2-)
    SCRIPT_PATH=$(echo "$EXEC_START" | awk '{print $2}')
    if [ -f "$SCRIPT_PATH" ]; then
        print_success "ExecStart script exists: $SCRIPT_PATH"
    else
        print_error "ExecStart script missing: $SCRIPT_PATH"
    fi
    
    # Check PYTHONPATH
    PYTHON_PATH=$(grep "PYTHONPATH=" "$SERVICE_FILE" | cut -d= -f2)
    if [ -d "$PYTHON_PATH" ]; then
        print_success "PYTHONPATH directory exists: $PYTHON_PATH"
    else
        print_error "PYTHONPATH directory missing: $PYTHON_PATH"
    fi
    
else
    print_error "Service file missing: $SERVICE_FILE"
fi

print_header "7. DEPENDENCIES CHECK"

echo "Checking Python dependencies..."

# Check required Python packages
REQUIRED_PACKAGES="flask flask_cors requests psutil"
for package in $REQUIRED_PACKAGES; do
    if python3 -c "import $package" 2>/dev/null; then
        print_success "Python package available: $package"
    else
        print_error "Python package missing: $package"
        echo "Install with: pip3 install $package"
    fi
done

echo ""
echo "Checking system dependencies..."
SYSTEM_PACKAGES="nginx sqlite3"
for package in $SYSTEM_PACKAGES; do
    if command -v "$package" &>/dev/null; then
        print_success "System package available: $package"
    else
        print_warning "System package missing: $package"
    fi
done

print_header "8. PORT AVAILABILITY CHECK"

echo "Checking if API port 5000 is available..."
if netstat -tlnp | grep -q ":5000 "; then
    print_warning "Port 5000 is already in use:"
    netstat -tlnp | grep ":5000 "
    echo "This might prevent the service from starting"
else
    print_success "Port 5000 is available"
fi

print_header "9. PERMISSIONS CHECK"

echo "Checking file permissions..."
echo "Main script permissions:"
ls -la "$REMOTE_PATH/hosting_manager.py"

echo ""
echo "Directory ownership:"
ls -la "$REMOTE_PATH/" | head -5

# Check if files are owned by correct user
if [ "$(stat -c %U $REMOTE_PATH)" = "www-data" ]; then
    print_success "Directory owned by www-data"
else
    print_warning "Directory not owned by www-data"
    echo "Current owner: $(stat -c %U $REMOTE_PATH)"
    echo "Fix with: chown -R www-data:www-data $REMOTE_PATH"
fi

print_header "10. MANUAL START TEST"

echo "Attempting manual service start for detailed error info..."
echo "This will show exactly what's failing:"

cd "$REMOTE_PATH"
echo ""
echo "Running manual start command:"
echo "PYTHONPATH=/opt/hosting-manager/src python3 /opt/hosting-manager/hosting_manager.py --api"
echo ""

# Attempt manual start with timeout
timeout 15 bash -c "
export PYTHONPATH=/opt/hosting-manager/src
export PYTHONUNBUFFERED=1
python3 /opt/hosting-manager/hosting_manager.py --api
" 2>&1 | head -20

print_header "11. DIAGNOSIS SUMMARY"

echo ""
echo "Common fixes based on what we found:"
echo ""

# Check for modular architecture issues
if [ ! -f "$REMOTE_PATH/src/api/app.py" ]; then
    print_error "ISSUE: Modular architecture files missing"
    echo "FIX: Complete the migration to modular architecture"
    echo "  - Ensure all files from the refactored structure are deployed"
    echo "  - Check src/api/app.py, src/api/routes/, src/api/services/ exist"
fi

# Check for import path issues  
if python3 -c "import sys; sys.path.insert(0, '/opt/hosting-manager/src'); import api.app" 2>/dev/null; then
    echo "✅ Modular imports working"
else
    print_error "ISSUE: Import path problems"
    echo "FIX: Ensure PYTHONPATH is set correctly in service file"
    echo "  - PYTHONPATH should point to /opt/hosting-manager/src"
    echo "  - All __init__.py files should exist"
fi

# Check for service file issues
if [ ! -f "/etc/systemd/system/hosting-manager.service" ]; then
    print_error "ISSUE: Service file missing"
    echo "FIX: Recreate service file with correct paths"
fi

print_header "12. QUICK FIXES"

echo "Try these fixes in order:"
echo ""

echo "1. Ensure all __init__.py files exist:"
echo "   find /opt/hosting-manager/src -type d -exec touch {}/__init__.py \;"
echo ""

echo "2. Fix permissions:"
echo "   chown -R www-data:www-data /opt/hosting-manager"
echo "   chmod +x /opt/hosting-manager/hosting_manager.py"
echo ""

echo "3. Reload systemd and restart:"
echo "   systemctl daemon-reload"
echo "   systemctl restart hosting-manager"
echo ""

echo "4. If still failing, check detailed logs:"
echo "   journalctl -u hosting-manager -f"
echo ""

echo "5. Test manual start:"
echo "   cd /opt/hosting-manager"
echo "   PYTHONPATH=/opt/hosting-manager/src python3 hosting_manager.py --api"

print_header "TROUBLESHOOTING COMPLETE"

echo ""
echo "If the service is still not starting after these fixes:"
echo "1. Check the manual start output above for specific errors"
echo "2. Look at journalctl -u hosting-manager -f while starting"
echo "3. Verify all files from the modular architecture are present"
echo "4. Consider rolling back to a backup if available"