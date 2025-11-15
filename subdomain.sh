#!/bin/bash
# debug-subdomain-deployment.sh - Systematic debugging of subdomain deployment

set -e

API_HOST="${API_HOST:-75.119.141.162}"
API_PORT="${API_PORT:-5000}"
BASE_URL="http://${API_HOST}:${API_PORT}"
TEST_TIMESTAMP=$(date +%s)
TEST_SUBDOMAIN="debug${TEST_TIMESTAMP}"
TEST_PARENT_DOMAIN="datablox.co.za"
FULL_DOMAIN="${TEST_SUBDOMAIN}.${TEST_PARENT_DOMAIN}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Enhanced API call with detailed error logging
debug_api_call() {
    local method="$1"
    local endpoint="$2"
    local data="$3"
    local description="$4"
    
    print_step "$description: $method $endpoint"
    
    local response
    local http_code
    
    if [ -n "$data" ]; then
        response=$(curl -s -w '\n%{http_code}' -X "$method" \
            -H 'Content-Type: application/json' \
            -d "$data" \
            "${BASE_URL}${endpoint}" 2>/dev/null)
    else
        response=$(curl -s -w '\n%{http_code}' -X "$method" \
            "${BASE_URL}${endpoint}" 2>/dev/null)
    fi
    
    http_code=$(echo "$response" | tail -n1)
    local response_body=$(echo "$response" | head -n -1)
    
    echo "HTTP Code: $http_code"
    echo "Response:"
    if command -v jq &> /dev/null; then
        echo "$response_body" | jq '.' 2>/dev/null || echo "$response_body"
    else
        echo "$response_body"
    fi
    echo ""
    
    # Return the HTTP code for further processing
    return $http_code
}

# Step 1: Test domain availability multiple times
test_domain_availability() {
    print_step "=== STEP 1: Testing Domain Availability ==="
    
    local availability_data='{
        "subdomain": "'$TEST_SUBDOMAIN'",
        "parent_domain": "'$TEST_PARENT_DOMAIN'"
    }'
    
    for i in {1..3}; do
        echo "--- Attempt $i ---"
        debug_api_call "POST" "/api/domains/check-availability" "$availability_data" "Domain availability check #$i"
        sleep 1
    done
}

# Step 2: Check nginx directly
test_nginx_check() {
    print_step "=== STEP 2: Direct Nginx Check ==="
    
    local nginx_data='{
        "domain": "'$FULL_DOMAIN'"
    }'
    
    debug_api_call "POST" "/api/nginx/check-domain" "$nginx_data" "Direct nginx domain check"
}

# Step 3: Check database directly
test_database_check() {
    print_step "=== STEP 3: Database Check ==="
    
    # Get all domains to see if our test domain exists
    debug_api_call "GET" "/api/domains/subdomains?parent_domain=${TEST_PARENT_DOMAIN}" "" "List existing subdomains"
}

# Step 4: Test simple subdomain creation
test_simple_subdomain_creation() {
    print_step "=== STEP 4: Simple Subdomain Creation ==="
    
    local subdomain_data='{
        "subdomain": "'$TEST_SUBDOMAIN'",
        "parent_domain": "'$TEST_PARENT_DOMAIN'",
        "app_name": "debug-app-'$TEST_TIMESTAMP'"
    }'
    
    debug_api_call "POST" "/api/domains/subdomains" "$subdomain_data" "Create simple subdomain"
}

# Step 5: Test full deployment with minimal data
test_minimal_deployment() {
    print_step "=== STEP 5: Minimal Next.js Deployment ==="
    
    local minimal_files='{
        "package.json": "{\"name\":\"debug-app\",\"version\":\"1.0.0\",\"scripts\":{\"start\":\"node server.js\"},\"dependencies\":{\"express\":\"^4.18.0\"}}",
        "server.js": "const express = require(\"express\"); const app = express(); const PORT = process.env.PORT || 3000; app.get(\"/\", (req, res) => res.send(\"Debug App\")); app.listen(PORT, () => console.log(`Running on ${PORT}`));"
    }'
    
    local deploy_data='{
        "name": "debug-app-'$TEST_TIMESTAMP'",
        "files": '$minimal_files',
        "domain_config": {
            "subdomain": "'$TEST_SUBDOMAIN'",
            "parent_domain": "'$TEST_PARENT_DOMAIN'"
        },
        "deployConfig": {
            "port": 3150
        }
    }'
    
    debug_api_call "POST" "/api/deploy/nodejs-subdomain" "$deploy_data" "Minimal deployment test"
}

# Step 6: Check server logs (if accessible)
check_server_status() {
    print_step "=== STEP 6: Server Status ==="
    
    debug_api_call "GET" "/api/status" "" "System status"
    debug_api_call "GET" "/api/processes" "" "Process list"
}

# Step 7: Test port availability
test_port_availability() {
    print_step "=== STEP 7: Port Availability ==="
    
    local port_data='{"startPort": 3140, "count": 20}'
    debug_api_call "POST" "/api/check-ports" "$port_data" "Port availability check"
}

# Step 8: Check logs for errors
check_deployment_logs() {
    print_step "=== STEP 8: Recent Deployment Logs ==="
    
    debug_api_call "GET" "/api/logs?limit=5" "" "Recent deployment logs"
}

# Main debugging sequence
main() {
    echo "=========================================="
    echo " Subdomain Deployment Debug Session"
    echo "=========================================="
    echo "Target Domain: $FULL_DOMAIN"
    echo "Timestamp: $TEST_TIMESTAMP"
    echo "=========================================="
    
    test_domain_availability
    test_nginx_check
    test_database_check
    test_port_availability
    check_server_status
    check_deployment_logs
    
    echo ""
    print_step "=== ATTEMPTING ACTUAL DEPLOYMENT ==="
    test_simple_subdomain_creation
    
    echo ""
    print_step "=== ATTEMPTING FULL DEPLOYMENT ==="
    test_minimal_deployment
    
    echo ""
    echo "=========================================="
    echo " Debug Session Complete"
    echo "=========================================="
    echo "Domain tested: $FULL_DOMAIN"
    echo ""
    echo "Next steps:"
    echo "1. Check server logs: journalctl -u hosting-manager -n 50"
    echo "2. Check nginx error logs: tail -50 /var/log/nginx/error.log"
    echo "3. Check database: sqlite3 /tmp/hosting/hosting.db 'SELECT * FROM domains ORDER BY created_at DESC LIMIT 10;'"
    echo "4. Check PM2 processes: pm2 list"
}

main "$@"