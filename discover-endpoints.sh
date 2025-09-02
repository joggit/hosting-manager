#!/bin/bash
# discover-all-endpoints.sh - Comprehensive endpoint discovery and testing for Hosting Manager API

REMOTE_HOST="${1:-75.119.141.162}"
API_URL="http://$REMOTE_HOST:5000"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

print_header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_info() { echo -e "${YELLOW}ℹ️  $1${NC}"; }
print_endpoint() { echo -e "${CYAN}🔗 $1${NC}"; }
print_category() { echo -e "${PURPLE}📁 $1${NC}"; }

# Function to test an endpoint
test_endpoint() {
    local method="$1"
    local endpoint="$2"
    local description="$3"
    local test_data="$4"
    
    printf "%-8s %-50s " "$method" "$endpoint"
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "%{http_code}" "$API_URL$endpoint" 2>/dev/null)
        http_code="${response: -3}"
        response_body="${response%???}"
    elif [ "$method" = "POST" ]; then
        if [ -n "$test_data" ]; then
            response=$(curl -s -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "$test_data" "$API_URL$endpoint" 2>/dev/null)
        else
            response=$(curl -s -w "%{http_code}" -X POST "$API_URL$endpoint" 2>/dev/null)
        fi
        http_code="${response: -3}"
        response_body="${response%???}"
    elif [ "$method" = "DELETE" ]; then
        response=$(curl -s -w "%{http_code}" -X DELETE "$API_URL$endpoint" 2>/dev/null)
        http_code="${response: -3}"
        response_body="${response%???}"
    else
        echo -e "${YELLOW}SKIP${NC} - Method not implemented in test"
        return
    fi
    
    case "$http_code" in
        200|201) 
            echo -e "${GREEN}OK${NC}   ($http_code) - $description"
            ;;
        404) 
            echo -e "${YELLOW}404${NC}  ($http_code) - Endpoint not found"
            ;;
        400) 
            echo -e "${YELLOW}400${NC}  ($http_code) - Bad request (expected for some tests)"
            ;;
        500) 
            echo -e "${RED}500${NC}  ($http_code) - Server error"
            ;;
        000) 
            echo -e "${RED}FAIL${NC} - Connection failed"
            ;;
        *) 
            echo -e "${YELLOW}$http_code${NC} - $description"
            ;;
    esac
}

# Function to extract endpoints from Python files
extract_python_endpoints() {
    local file="$1"
    
    if [ ! -f "$file" ]; then
        return
    fi
    
    echo "# Endpoints found in $file:" >> /tmp/discovered_endpoints.txt
    
    # Extract @app.route decorators
    grep -n "@.*\.route\|@.*app.*route" "$file" | while read -r line; do
        line_num=$(echo "$line" | cut -d: -f1)
        route_def=$(echo "$line" | cut -d: -f2-)
        
        # Extract the route path
        route_path=$(echo "$route_def" | sed -n 's/.*route("\([^"]*\)".*/\1/p')
        
        # Extract methods if specified
        methods=$(echo "$route_def" | sed -n 's/.*methods=\[\([^]]*\)\].*/\1/p' | tr -d '"' | tr -d "'" | tr ',' ' ')
        
        if [ -z "$methods" ]; then
            methods="GET"
        fi
        
        # Get the function name (next non-empty line that defines a function)
        func_line=$((line_num + 1))
        func_name=$(sed -n "${func_line}p" "$file" | sed -n 's/.*def \([^(]*\).*/\1/p')
        
        if [ -n "$route_path" ]; then
            echo "  $methods $route_path  # $func_name" >> /tmp/discovered_endpoints.txt
        fi
    done
    
    echo "" >> /tmp/discovered_endpoints.txt
}

print_header "HOSTING MANAGER API ENDPOINT DISCOVERY"
echo "🔍 Scanning for all available endpoints..."
echo "🌐 API URL: $API_URL"

# Clear previous results
> /tmp/discovered_endpoints.txt

print_header "1. EXTRACTING ENDPOINTS FROM SOURCE CODE"

# Check if we're in the project directory or need to scan uploaded files
if [ -f "src/api/server.py" ]; then
    echo "📁 Scanning local source files..."
    extract_python_endpoints "src/api/server.py"
    extract_python_endpoints "src/api/nextjs_monitoring.py"
    extract_python_endpoints "hosting_manager.py"
    
    echo "📄 Discovered endpoints written to /tmp/discovered_endpoints.txt"
    cat /tmp/discovered_endpoints.txt
else
    echo "📄 No local source files found, using predefined endpoint list..."
fi

print_header "2. COMPREHENSIVE ENDPOINT TESTING"

echo "Testing all known endpoints from the hosting manager codebase..."
echo ""
printf "%-8s %-50s %s\n" "METHOD" "ENDPOINT" "STATUS"
echo "$(printf '%*s' 80 | tr ' ' '-')"

print_category "CORE API ENDPOINTS"
test_endpoint "GET" "/api/health" "Health check and system info"
test_endpoint "GET" "/api/status" "Comprehensive system status"
test_endpoint "GET" "/api/processes" "All managed processes"
test_endpoint "GET" "/api/domains" "List all domains"
test_endpoint "GET" "/api/logs" "Deployment logs"

print_category "PROCESS MANAGEMENT"
test_endpoint "GET" "/api/processes/test-process" "Process details (test process)"
test_endpoint "POST" "/api/processes/test-process/start" "Start process"
test_endpoint "POST" "/api/processes/test-process/stop" "Stop process" 
test_endpoint "POST" "/api/processes/test-process/restart" "Restart process"
test_endpoint "GET" "/api/processes/test-process/logs" "Process logs"

print_category "PM2 MANAGEMENT"
test_endpoint "GET" "/api/pm2/status" "PM2 daemon status"
test_endpoint "GET" "/api/pm2/list" "PM2 process list"
test_endpoint "POST" "/api/pm2/test-app/start" "PM2 start action"
test_endpoint "POST" "/api/pm2/test-app/stop" "PM2 stop action"
test_endpoint "POST" "/api/pm2/test-app/restart" "PM2 restart action"
test_endpoint "POST" "/api/pm2/test-app/reload" "PM2 reload action"
test_endpoint "POST" "/api/pm2/test-app/delete" "PM2 delete action"

print_category "DEPLOYMENT"
# Test data for Node.js deployment
NODEJS_DEPLOY_DATA='{
  "name": "test-deploy",
  "files": {
    "package.json": "{\"name\":\"test\",\"main\":\"app.js\",\"scripts\":{\"start\":\"node app.js\"}}",
    "app.js": "console.log(\"Hello World\");"
  },
  "deployConfig": {"port": 3001}
}'

test_endpoint "POST" "/api/deploy/nodejs" "Deploy Node.js application" "$NODEJS_DEPLOY_DATA"

DOMAIN_DEPLOY_DATA='{"domain_name": "test.example.com", "port": 3001, "site_type": "node"}'
test_endpoint "POST" "/api/domains" "Deploy new domain" "$DOMAIN_DEPLOY_DATA"
test_endpoint "DELETE" "/api/domains/test.example.com" "Remove domain"

print_category "MONITORING - DASHBOARD & OVERVIEW"
test_endpoint "GET" "/api/monitoring/dashboard" "Complete dashboard overview"
test_endpoint "GET" "/api/monitoring/sites" "All sites monitoring status"
test_endpoint "GET" "/api/monitoring/health" "Health check status"
test_endpoint "GET" "/api/monitoring/metrics" "System performance metrics"
test_endpoint "GET" "/api/monitoring/alerts" "Active system alerts"

print_category "MONITORING - SYSTEM RESOURCES"
test_endpoint "GET" "/api/monitoring/system/resources" "Real-time system resources"
test_endpoint "GET" "/api/monitoring/deployment/status" "Deployment overview"

print_category "MONITORING - DETAILED"
test_endpoint "GET" "/api/monitoring/sites/test-site" "Site detailed monitoring"
test_endpoint "GET" "/api/monitoring/logs/stream/test-site" "Stream site logs"
test_endpoint "GET" "/api/monitoring/nginx" "Nginx monitoring status"
test_endpoint "GET" "/api/monitoring/pm2/detailed" "Detailed PM2 status"

print_category "MONITORING - AUDIT"
test_endpoint "GET" "/api/monitoring/audit/quick" "Quick nginx/PM2 audit"
test_endpoint "GET" "/api/monitoring/audit/sites" "Full site audit"

print_category "SITE INFORMATION"
test_endpoint "GET" "/api/sites" "Comprehensive sites information"
test_endpoint "GET" "/api/sites/test.example.com/details" "Site detailed info"
test_endpoint "GET" "/api/sites/test.example.com/nginx-config" "Site nginx config"
test_endpoint "GET" "/api/sites/connectivity" "Sites connectivity test"

print_category "NGINX MANAGEMENT"
test_endpoint "GET" "/api/nginx/status" "Nginx status and config"
test_endpoint "GET" "/api/nginx/sites-enabled" "Nginx enabled sites"

print_category "SERVER & NETWORK"
test_endpoint "GET" "/api/server/network-info" "Server network information"
test_endpoint "POST" "/api/check-ports" "Check available ports" '{"startPort": 3001, "count": 5}'

print_header "3. ENDPOINT SUMMARY BY CATEGORY"

echo ""
print_category "🏥 HEALTH & STATUS (3 endpoints)"
echo "  GET  /api/health                          - Basic health check"
echo "  GET  /api/status                          - System status with monitoring"  
echo "  GET  /api/monitoring/dashboard            - Complete dashboard for React frontend"

print_category "⚙️  PROCESS MANAGEMENT (5 endpoints)"
echo "  GET  /api/processes                       - List all processes"
echo "  GET  /api/processes/<name>                - Process details"
echo "  POST /api/processes/<name>/start          - Start process"
echo "  POST /api/processes/<name>/stop           - Stop process"  
echo "  POST /api/processes/<name>/restart        - Restart process"
echo "  GET  /api/processes/<name>/logs           - Get process logs"

print_category "🚀 PM2 MANAGEMENT (8 endpoints)"
echo "  GET  /api/pm2/status                      - PM2 daemon status"
echo "  GET  /api/pm2/list                        - List PM2 processes"
echo "  POST /api/pm2/<name>/start                - Start PM2 process"
echo "  POST /api/pm2/<name>/stop                 - Stop PM2 process"
echo "  POST /api/pm2/<name>/restart              - Restart PM2 process"
echo "  POST /api/pm2/<name>/reload               - Reload PM2 process" 
echo "  POST /api/pm2/<name>/delete               - Delete PM2 process"
echo "  GET  /api/monitoring/pm2/detailed         - Detailed PM2 monitoring"

print_category "📦 DEPLOYMENT (3 endpoints)"
echo "  POST /api/deploy/nodejs                   - Deploy Node.js application"
echo "  GET  /api/domains                         - List domains"
echo "  POST /api/domains                         - Deploy new domain"
echo "  DELETE /api/domains/<name>                - Remove domain"

print_category "📊 MONITORING & HEALTH (12 endpoints)" 
echo "  GET  /api/monitoring/dashboard            - Dashboard overview"
echo "  GET  /api/monitoring/sites                - All sites status"
echo "  GET  /api/monitoring/sites/<name>         - Site detailed monitoring"
echo "  GET  /api/monitoring/health               - Health checks overview"
echo "  GET  /api/monitoring/metrics              - Performance metrics"
echo "  GET  /api/monitoring/alerts               - Active alerts"
echo "  GET  /api/monitoring/system/resources     - System resources"
echo "  GET  /api/monitoring/nginx                - Nginx monitoring"
echo "  GET  /api/monitoring/deployment/status    - Deployment status"
echo "  GET  /api/monitoring/logs/stream/<name>   - Stream logs"
echo "  GET  /api/monitoring/audit/quick          - Quick audit"
echo "  GET  /api/monitoring/audit/sites          - Full audit"

print_category "🌐 SITE & NGINX INFO (7 endpoints)"
echo "  GET  /api/sites                           - All sites comprehensive info"
echo "  GET  /api/sites/<name>/details            - Site detailed info"
echo "  GET  /api/sites/<name>/nginx-config       - Site nginx configuration"
echo "  GET  /api/sites/connectivity              - Test connectivity"
echo "  GET  /api/nginx/status                    - Nginx status"
echo "  GET  /api/nginx/sites-enabled             - Nginx enabled sites"
echo "  GET  /api/server/network-info             - Server network info"

print_category "🔧 UTILITIES (2 endpoints)"
echo "  GET  /api/logs                            - Deployment logs"
echo "  POST /api/check-ports                     - Check available ports"

print_header "4. QUICK TEST COMMANDS"

echo ""
echo "# Basic health and status"
echo "curl $API_URL/api/health | jq"
echo "curl $API_URL/api/status | jq"
echo ""
echo "# PM2 management"
echo "curl $API_URL/api/pm2/status | jq"
echo "curl $API_URL/api/pm2/list | jq"
echo ""
echo "# Monitoring dashboard (for React frontend)"
echo "curl $API_URL/api/monitoring/dashboard | jq"
echo "curl $API_URL/api/monitoring/sites | jq"
echo "curl $API_URL/api/monitoring/system/resources | jq"
echo ""
echo "# Site information"
echo "curl $API_URL/api/sites | jq"
echo "curl $API_URL/api/nginx/status | jq"
echo ""
echo "# Process management"
echo "curl $API_URL/api/processes | jq"
echo ""
echo "# Deploy Node.js app"
echo "curl -X POST -H 'Content-Type: application/json' \\"
echo "  -d '{\"name\":\"test\",\"files\":{\"app.js\":\"console.log('hello')\"}}' \\"
echo "  $API_URL/api/deploy/nodejs | jq"

print_header "5. INTERACTIVE ENDPOINT EXPLORER"

if command -v jq >/dev/null 2>&1; then
    echo ""
    echo "🔍 Select an endpoint category to explore:"
    echo ""
    echo "1) Health & Status"
    echo "2) Process Management" 
    echo "3) PM2 Management"
    echo "4) Monitoring Dashboard"
    echo "5) Site Information"
    echo "6) System Resources"
    echo "7) Full Test Suite"
    echo "8) Exit"
    echo ""
    read -p "Enter your choice (1-8): " choice
    
    case $choice in
        1)
            echo "Testing health endpoints..."
            curl -s "$API_URL/api/health" | jq .
            ;;
        2) 
            echo "Testing process endpoints..."
            curl -s "$API_URL/api/processes" | jq '.summary'
            ;;
        3)
            echo "Testing PM2 endpoints..."
            curl -s "$API_URL/api/pm2/status" | jq .
            ;;
        4)
            echo "Testing monitoring dashboard..."
            curl -s "$API_URL/api/monitoring/dashboard" | jq '.dashboard.summary'
            ;;
        5)
            echo "Testing site information..."
            curl -s "$API_URL/api/sites" | jq '.summary'
            ;;
        6)
            echo "Testing system resources..."
            curl -s "$API_URL/api/monitoring/system/resources" | jq '.resources | {cpu: .cpu.usage_percent, memory: .memory.percentage, disk: .disk.percentage}'
            ;;
        7)
            echo "Running comprehensive test suite..."
            echo "This would run all endpoint tests with detailed output..."
            ;;
        8)
            echo "Exiting endpoint explorer."
            ;;
        *)
            echo "Invalid choice. Exiting."
            ;;
    esac
else
    echo "💡 Install 'jq' for better JSON formatting: apt install jq"
fi

print_header "✨ ENDPOINT DISCOVERY COMPLETE"

echo ""
echo "📋 TOTAL ENDPOINTS DISCOVERED: ~40+"
echo ""
echo "🏗️  ARCHITECTURE OVERVIEW:"
echo "   - Core hosting management (domains, processes)"
echo "   - PM2 process manager integration"  
echo "   - Real-time monitoring & health checks"
echo "   - Nginx configuration management"
echo "   - Next.js multisite hosting support"
echo "   - React frontend dashboard APIs"
echo "   - System resource monitoring"
echo "   - Comprehensive site information"
echo ""
echo "🎯 NEXT STEPS:"
echo "   1. Use the monitoring endpoints for your React dashboard"
echo "   2. Implement PM2 process management in your frontend"
echo "   3. Add site deployment workflows"
echo "   4. Create system health monitoring displays"
echo "   5. Build nginx configuration management UI"
echo ""
echo "🔧 API DOCUMENTATION: $API_URL/api/health"
echo "📊 Dashboard Data: $API_URL/api/monitoring/dashboard"
echo "🌐 All Sites: $API_URL/api/sites"

# Cleanup
rm -f /tmp/discovered_endpoints.txt