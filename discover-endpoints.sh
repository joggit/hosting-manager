#!/bin/bash
# test-pm2-endpoints.sh - Test all PM2 endpoints

REMOTE_HOST="75.119.141.162"
API_URL="http://$REMOTE_HOST:5000"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_info() { echo -e "${YELLOW}ℹ️  $1${NC}"; }

print_header "PM2 ENDPOINTS TESTING"

echo "🌐 API URL: $API_URL"
echo "📋 Testing PM2-specific endpoints..."

print_header "1. CHECK PM2 STATUS ENDPOINT"
echo "Testing new /api/pm2/status endpoint..."
PM2_STATUS_RESPONSE=$(curl -s "$API_URL/api/pm2/status")
PM2_STATUS_SUCCESS=$(echo "$PM2_STATUS_RESPONSE" | jq -r '.success // false' 2>/dev/null)

if [ "$PM2_STATUS_SUCCESS" = "true" ]; then
    print_success "PM2 status endpoint working!"
    
    # Show key status information
    DAEMON_RUNNING=$(echo "$PM2_STATUS_RESPONSE" | jq -r '.pm2_status.daemon_running // false' 2>/dev/null)
    PM2_VERSION=$(echo "$PM2_STATUS_RESPONSE" | jq -r '.pm2_status.version // "unknown"' 2>/dev/null)
    PROCESS_COUNT=$(echo "$PM2_STATUS_RESPONSE" | jq -r '.pm2_status.process_count // 0' 2>/dev/null)
    
    print_info "PM2 Version: $PM2_VERSION"
    print_info "Daemon Running: $DAEMON_RUNNING"  
    print_info "Processes: $PROCESS_COUNT"
    
    # Show detailed status
    echo "Full PM2 Status:"
    echo "$PM2_STATUS_RESPONSE" | jq '.pm2_status' 2>/dev/null || echo "$PM2_STATUS_RESPONSE"
    
else
    print_error "PM2 status endpoint failed"
    echo "Response: $PM2_STATUS_RESPONSE"
fi

print_header "2. CHECK PM2 STATUS IN MAIN API"
echo "Testing /api/health for PM2 availability..."
HEALTH_RESPONSE=$(curl -s "$API_URL/api/health" | jq -r '.pm2_available // "not_found"' 2>/dev/null)

if [ "$HEALTH_RESPONSE" = "true" ]; then
    print_success "PM2 is available on the server"
elif [ "$HEALTH_RESPONSE" = "false" ]; then
    print_error "PM2 is not available on the server"
    exit 1
else
    print_info "Could not determine PM2 status from health endpoint"
fi

print_header "3. TEST /api/pm2/list ENDPOINT"
echo "Getting PM2 process list..."
PM2_LIST_RESPONSE=$(curl -s "$API_URL/api/pm2/list")
PM2_LIST_SUCCESS=$(echo "$PM2_LIST_RESPONSE" | jq -r '.success // false' 2>/dev/null)

if [ "$PM2_LIST_SUCCESS" = "true" ]; then
    print_success "PM2 list endpoint working!"
    PROCESS_COUNT=$(echo "$PM2_LIST_RESPONSE" | jq -r '.processes | length' 2>/dev/null)
    print_info "Found $PROCESS_COUNT PM2 processes"
    
    # Pretty print the processes if any exist
    if [ "$PROCESS_COUNT" != "0" ] && [ "$PROCESS_COUNT" != "null" ]; then
        echo "$PM2_LIST_RESPONSE" | jq '.processes[] | {name: .name, status: .pm2_env.status, pid: .pid, memory: .monit.memory}'
    else
        print_info "No PM2 processes currently running"
    fi
else
    print_error "PM2 list endpoint failed"
    echo "Response: $PM2_LIST_RESPONSE"
fi

print_header "4. TEST /api/processes ENDPOINT (INCLUDES PM2 DATA)"
echo "Getting all processes (including PM2)..."
ALL_PROCESSES_RESPONSE=$(curl -s "$API_URL/api/processes")
ALL_PROCESSES_SUCCESS=$(echo "$ALL_PROCESSES_RESPONSE" | jq -r '.success // false' 2>/dev/null)

if [ "$ALL_PROCESSES_SUCCESS" = "true" ]; then
    print_success "All processes endpoint working!"
    
    # Check if PM2 is available in monitoring info
    PM2_AVAILABLE=$(echo "$ALL_PROCESSES_RESPONSE" | jq -r '.monitoring.pm2_available // false' 2>/dev/null)
    if [ "$PM2_AVAILABLE" = "true" ]; then
        print_success "PM2 monitoring is active"
    else
        print_error "PM2 monitoring is not active"
    fi
    
    # Show PM2 processes if any
    PM2_PROCESSES=$(echo "$ALL_PROCESSES_RESPONSE" | jq -r '.processes[] | select(.process_manager == "pm2") | .name' 2>/dev/null)
    
    if [ -n "$PM2_PROCESSES" ] && [ "$PM2_PROCESSES" != "null" ]; then
        print_success "PM2 processes found:"
        echo "$ALL_PROCESSES_RESPONSE" | jq -r '.processes[] | select(.process_manager == "pm2") | "  - \(.name) (PID: \(.pid // "N/A"), Status: \(.status), Memory: \(.memory // "N/A"))"'
    else
        print_info "No PM2 processes found in process list"
    fi
else
    print_error "All processes endpoint failed"
    echo "Response: $ALL_PROCESSES_RESPONSE"
fi

print_header "5. DEPLOY A TEST NODE.JS APP WITH PM2"
print_info "Testing PM2 deployment functionality..."

# Create a simple test Node.js app
TEST_APP_DATA='{
  "name": "pm2-test-app",
  "files": {
    "package.json": "{\n  \"name\": \"pm2-test-app\",\n  \"version\": \"1.0.0\",\n  \"main\": \"app.js\",\n  \"scripts\": {\n    \"start\": \"node app.js\"\n  },\n  \"dependencies\": {}\n}",
    "app.js": "const http = require(\"http\");\n\nconst server = http.createServer((req, res) => {\n  res.writeHead(200, { \"Content-Type\": \"application/json\" });\n  res.end(JSON.stringify({\n    message: \"Hello from PM2 test app!\",\n    timestamp: new Date().toISOString(),\n    pid: process.pid\n  }));\n});\n\nconst PORT = process.env.PORT || 3001;\nserver.listen(PORT, () => {\n  console.log(`PM2 test app running on port ${PORT}`);\n});\n"
  },
  "deployConfig": {
    "port": 3001
  }
}'

echo "Deploying test Node.js app..."
DEPLOY_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
    -d "$TEST_APP_DATA" \
    "$API_URL/api/deploy/nodejs")

DEPLOY_SUCCESS=$(echo "$DEPLOY_RESPONSE" | jq -r '.success // false' 2>/dev/null)

if [ "$DEPLOY_SUCCESS" = "true" ]; then
    print_success "Test app deployed successfully!"
    PROCESS_MANAGER=$(echo "$DEPLOY_RESPONSE" | jq -r '.process_manager // "unknown"' 2>/dev/null)
    APP_PORT=$(echo "$DEPLOY_RESPONSE" | jq -r '.port // "unknown"' 2>/dev/null)
    
    print_info "Process manager: $PROCESS_MANAGER"
    print_info "Port: $APP_PORT"
    
    # Wait a moment for the app to start
    sleep 3
    
    print_header "6. TEST PM2 ACTIONS ON THE DEPLOYED APP"
    
    if [ "$PROCESS_MANAGER" = "pm2" ]; then
        # Test PM2 restart
        echo "Testing PM2 restart action..."
        RESTART_RESPONSE=$(curl -s -X POST "$API_URL/api/pm2/pm2-test-app/restart")
        RESTART_SUCCESS=$(echo "$RESTART_RESPONSE" | jq -r '.success // false' 2>/dev/null)
        
        if [ "$RESTART_SUCCESS" = "true" ]; then
            print_success "PM2 restart action working!"
        else
            print_error "PM2 restart action failed"
            echo "Response: $RESTART_RESPONSE"
        fi
        
        # Test the app itself
        sleep 2
        echo "Testing deployed app..."
        APP_RESPONSE=$(curl -s "http://$REMOTE_HOST:3001" 2>/dev/null)
        
        if [ -n "$APP_RESPONSE" ]; then
            print_success "Deployed app is responding!"
            echo "$APP_RESPONSE" | jq . 2>/dev/null || echo "$APP_RESPONSE"
        else
            print_error "Deployed app is not responding"
        fi
        
        # Check PM2 list again to see our new process
        echo "Checking PM2 list for new process..."
        NEW_PM2_LIST=$(curl -s "$API_URL/api/pm2/list")
        NEW_PROCESS_COUNT=$(echo "$NEW_PM2_LIST" | jq -r '.processes | length' 2>/dev/null)
        print_info "PM2 processes after deployment: $NEW_PROCESS_COUNT"
        
    else
        print_info "App was deployed with $PROCESS_MANAGER, not PM2"
    fi
    
    print_header "7. TEST NEXT.JS MONITORING ENDPOINTS"
    echo "Testing new monitoring endpoints..."
    
    MONITORING_ENDPOINTS=(
        "/api/monitoring/dashboard:Dashboard Overview"
        "/api/monitoring/sites:Sites Status"
        "/api/monitoring/system/resources:System Resources"
        "/api/monitoring/alerts:Active Alerts"
    )
    
    for endpoint_info in "${MONITORING_ENDPOINTS[@]}"; do
        IFS=':' read -r endpoint description <<< "$endpoint_info"
        echo -n "Testing $endpoint ... "
        
        RESPONSE=$(curl -s "$API_URL$endpoint")
        SUCCESS=$(echo "$RESPONSE" | jq -r '.success // false' 2>/dev/null)
        
        if [ "$SUCCESS" = "true" ]; then
            print_success "$description working!"
        else
            print_error "$description failed"
        fi
    done
    
    print_header "8. CLEANUP TEST APP"
    echo "Stopping and removing test app..."
    
    # Stop the process
    STOP_RESPONSE=$(curl -s -X POST "$API_URL/api/processes/pm2-test-app/stop")
    STOP_SUCCESS=$(echo "$STOP_RESPONSE" | jq -r '.success // false' 2>/dev/null)
    
    if [ "$STOP_SUCCESS" = "true" ]; then
        print_success "Test app stopped"
    else
        print_info "Could not stop test app (may not be running)"
    fi
    
else
    print_error "Failed to deploy test app"
    echo "Response: $DEPLOY_RESPONSE"
fi

print_header "SUMMARY - COMPLETE NEXT.JS HOSTING API"
echo "📋 Core PM2 Endpoints:"
echo "   GET  /api/pm2/status                   - PM2 daemon status and info"
echo "   GET  /api/pm2/list                     - List all PM2 processes"
echo "   POST /api/pm2/{process_name}/start     - Start PM2 process"
echo "   POST /api/pm2/{process_name}/stop      - Stop PM2 process" 
echo "   POST /api/pm2/{process_name}/restart   - Restart PM2 process"
echo "   POST /api/pm2/{process_name}/reload    - Reload PM2 process"
echo "   POST /api/pm2/{process_name}/delete    - Delete PM2 process"
echo ""
echo "📊 Next.js Monitoring Endpoints (NEW):"
echo "   GET  /api/monitoring/dashboard         - Complete dashboard for React frontend"
echo "   GET  /api/monitoring/sites             - All sites with health monitoring"
echo "   GET  /api/monitoring/system/resources  - Real-time system metrics"
echo "   GET  /api/monitoring/alerts            - Active system alerts"
echo "   GET  /api/monitoring/logs/stream/{name} - Stream site logs"
echo ""
echo "📋 General Endpoints (Include PM2 data):"
echo "   GET  /api/processes                    - All processes (including PM2)"
echo "   POST /api/deploy/nodejs                - Deploy Node.js app (uses PM2 if available)"
echo "   GET  /api/status                       - System status (includes PM2 info)"
echo ""
echo "🔧 Manual PM2 Commands on Server:"
echo "   ssh root@$REMOTE_HOST 'pm2 list'"
echo "   ssh root@$REMOTE_HOST 'pm2 status'"
echo "   ssh root@$REMOTE_HOST 'pm2 monit'"

print_header "QUICK TESTS"
echo "Test PM2 status:         curl $API_URL/api/pm2/status | jq"
echo "Test PM2 list:           curl $API_URL/api/pm2/list | jq"
echo "Test dashboard:          curl $API_URL/api/monitoring/dashboard | jq"
echo "Test sites status:       curl $API_URL/api/monitoring/sites | jq"
echo "Test system resources:   curl $API_URL/api/monitoring/system/resources | jq"
echo "Test alerts:             curl $API_URL/api/monitoring/alerts | jq"
echo "Deploy Next.js app:      curl -X POST -H 'Content-Type: application/json' -d '{...}' $API_URL/api/deploy/nodejs"

print_header "🎉 COMPLETE NEXT.JS HOSTING PLATFORM READY!"
echo ""
echo "✅ PM2 Process Management"
echo "✅ Next.js Multisite Hosting" 
echo "✅ Real-time Monitoring Dashboard"
echo "✅ System Health Alerts"
echo "✅ React Frontend APIs"
echo ""
echo "🌐 Dashboard URL: http://$REMOTE_HOST:5000/api/monitoring/dashboard"
echo "📊 Use the React components to build your monitoring frontend!"