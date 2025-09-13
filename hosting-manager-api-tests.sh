#!/bin/bash
# enhanced-hosting-test-with-retry.sh - Tests with retry functionality for failing routes

set -e

# Configuration
API_HOST="${API_HOST:-75.119.141.162}"
API_PORT="${API_PORT:-5000}"
BASE_URL="http://${API_HOST}:${API_PORT}"

# Test configuration
TEST_TIMESTAMP=$(date +%s)
TEST_PARENT_DOMAIN="datablox.co.za"
TEST_SUBDOMAIN="test${TEST_TIMESTAMP}"
TEST_FULL_DOMAIN="${TEST_SUBDOMAIN}.${TEST_PARENT_DOMAIN}"
TEST_APP_NAME="test-app-${TEST_TIMESTAMP}"
TEST_ROOT_DOMAIN="test-root-${TEST_TIMESTAMP}.datablox.co.za"

# Test modes
RUN_MODE="all"  # all, failed, interactive, single
RETRY_COUNT=3
RETRY_DELAY=2
FAILED_TESTS_FILE="/tmp/hosting-manager-failed-tests.log"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[TEST]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
print_section() { echo -e "${PURPLE}[SECTION]${NC} $1"; }

# Global variables for test tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
TEST_RESULTS=()
FAILED_TEST_DETAILS=()

# Test registry for individual test execution
declare -A TEST_FUNCTIONS
declare -A TEST_DESCRIPTIONS

# Register a test function
register_test() {
    local test_name="$1"
    local test_function="$2" 
    local description="$3"
    
    TEST_FUNCTIONS["$test_name"]="$test_function"
    TEST_DESCRIPTIONS["$test_name"]="$description"
}

# Function to track test results with details
track_test() {
    local test_name="$1"
    local result="$2"
    local endpoint="${3:-unknown}"
    local error_msg="${4:-}"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if [ "$result" -eq 0 ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        TEST_RESULTS+=("✅ $test_name")
        # Remove from failed tests if it was previously failing
        remove_from_failed_tests "$test_name"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        TEST_RESULTS+=("❌ $test_name")
        
        # Store failed test details
        local failure_info="$test_name|$endpoint|$error_msg|$(date '+%Y-%m-%d %H:%M:%S')"
        FAILED_TEST_DETAILS+=("$failure_info")
        echo "$failure_info" >> "$FAILED_TESTS_FILE"
    fi
}

# Remove a test from failed tests file
remove_from_failed_tests() {
    local test_name="$1"
    if [ -f "$FAILED_TESTS_FILE" ]; then
        grep -v "^$test_name|" "$FAILED_TESTS_FILE" > "${FAILED_TESTS_FILE}.tmp" || true
        mv "${FAILED_TESTS_FILE}.tmp" "$FAILED_TESTS_FILE"
    fi
}

# Enhanced API call function with retry
api_call_with_retry() {
    local method="$1"
    local endpoint="$2"
    local data="$3"
    local expected_status="${4:-200}"
    local description="${5:-API Call}"
    local max_retries="${6:-$RETRY_COUNT}"
    
    local attempt=1
    local success=false
    
    while [ $attempt -le $max_retries ] && [ "$success" = false ]; do
        if [ $attempt -gt 1 ]; then
            print_info "Retry attempt $attempt/$max_retries for: $description"
            sleep $RETRY_DELAY
        fi
        
        if api_call "$method" "$endpoint" "$data" "$expected_status" "$description"; then
            success=true
        else
            attempt=$((attempt + 1))
        fi
    done
    
    if [ "$success" = true ]; then
        return 0
    else
        print_error "Failed after $max_retries attempts: $description"
        return 1
    fi
}

# Original API call function
api_call() {
    local method="$1"
    local endpoint="$2"
    local data="$3"
    local expected_status="${4:-200}"
    local description="${5:-API Call}"
    
    print_status "$description: $method $endpoint"
    
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
    
    local curl_exit_code=$?
    
    if [ $curl_exit_code -ne 0 ]; then
        print_error "cURL failed with exit code $curl_exit_code"
        return 1
    fi
    
    # Extract HTTP status code and response body
    http_code=$(echo "$response" | tail -n1)
    local response_body=$(echo "$response" | head -n -1)
    
    echo "Response Code: $http_code"
    
    if command -v jq &> /dev/null && echo "$response_body" | jq empty 2>/dev/null; then
        echo "$response_body" | jq '.'
    else
        echo "Response Body: $response_body"
    fi
    
    if [ "$http_code" -eq "$expected_status" ]; then
        print_success "$description successful"
        return 0
    else
        print_error "$description failed (expected $expected_status, got $http_code)"
        return 1
    fi
}

# Individual test functions
test_health_check() {
    if api_call_with_retry "GET" "/api/health" "" 200 "Health check"; then
        track_test "Service Health Check" 0 "/api/health"
    else
        track_test "Service Health Check" 1 "/api/health" "Health endpoint not responding"
    fi
}

test_nginx_status() {
    if api_call_with_retry "GET" "/api/nginx/status" "" 200 "Nginx status"; then
        track_test "Nginx Status" 0 "/api/nginx/status"
    else
        track_test "Nginx Status" 1 "/api/nginx/status" "Nginx status endpoint failed"
    fi
}

test_nginx_sites_enabled() {
    if api_call_with_retry "GET" "/api/nginx/sites-enabled" "" 200 "Nginx sites-enabled"; then
        track_test "Nginx Sites Enabled" 0 "/api/nginx/sites-enabled"
    else
        track_test "Nginx Sites Enabled" 1 "/api/nginx/sites-enabled" "Sites-enabled endpoint failed"
    fi
}

test_comprehensive_sites_info() {
    if api_call_with_retry "GET" "/api/sites" "" 200 "Comprehensive sites info"; then
        track_test "Comprehensive Sites Info" 0 "/api/sites"
    else
        track_test "Comprehensive Sites Info" 1 "/api/sites" "Sites info endpoint failed"
    fi
}

test_sites_connectivity() {
    if api_call_with_retry "GET" "/api/sites/connectivity" "" 200 "Sites connectivity test"; then
        track_test "Sites Connectivity Test" 0 "/api/sites/connectivity"
    else
        track_test "Sites Connectivity Test" 1 "/api/sites/connectivity" "Connectivity test failed"
    fi
}

test_server_network_info() {
    if api_call_with_retry "GET" "/api/server/network-info" "" 200 "Server network info"; then
        track_test "Server Network Info" 0 "/api/server/network-info"
    else
        track_test "Server Network Info" 1 "/api/server/network-info" "Network info endpoint failed"
    fi
}

test_nginx_domain_check() {
    local nginx_domain_check='{
        "domain": "test-nginx-check.datablox.co.za"
    }'
    
    if api_call_with_retry "POST" "/api/nginx/check-domain" "$nginx_domain_check" 200 "Nginx domain check"; then
        track_test "Nginx Domain Check" 0 "/api/nginx/check-domain"
    else
        track_test "Nginx Domain Check" 1 "/api/nginx/check-domain" "Domain check endpoint failed"
    fi
}

test_domain_availability_subdomain() {
    local availability_check_subdomain='{
        "subdomain": "availability-test-'$TEST_TIMESTAMP'",
        "parent_domain": "datablox.co.za"
    }'
    
    if api_call_with_retry "POST" "/api/domains/check-availability" "$availability_check_subdomain" 200 "Domain availability (subdomain)"; then
        track_test "Enhanced Domain Availability (Subdomain)" 0 "/api/domains/check-availability"
    else
        track_test "Enhanced Domain Availability (Subdomain)" 1 "/api/domains/check-availability" "Subdomain availability check failed"
    fi
}

test_domain_availability_simple() {
    local availability_check_simple='{
        "domain": "simple-test-'$TEST_TIMESTAMP'.datablox.co.za"
    }'
    
    if api_call_with_retry "POST" "/api/domains/check-availability" "$availability_check_simple" 200 "Domain availability (simple)"; then
        track_test "Enhanced Domain Availability (Simple)" 0 "/api/domains/check-availability"
    else
        track_test "Enhanced Domain Availability (Simple)" 1 "/api/domains/check-availability" "Simple domain availability check failed"
    fi
}

test_subdomain_suggestions() {
    if api_call_with_retry "GET" "/api/domains/datablox.co.za/subdomains/suggestions?limit=10" "" 200 "Subdomain suggestions"; then
        track_test "Subdomain Suggestions" 0 "/api/domains/*/subdomains/suggestions"
    else
        track_test "Subdomain Suggestions" 1 "/api/domains/*/subdomains/suggestions" "Subdomain suggestions endpoint failed"
    fi
}

test_domain_cleanup_candidates() {
    if api_call_with_retry "GET" "/api/domains/cleanup" "" 200 "Domain cleanup candidates"; then
        track_test "Domain Cleanup Candidates" 0 "/api/domains/cleanup"
    else
        track_test "Domain Cleanup Candidates" 1 "/api/domains/cleanup" "Cleanup candidates endpoint failed"
    fi
}

test_domain_status() {
    if api_call_with_retry "GET" "/api/domains/status" "" 200 "Domain status"; then
        track_test "Domain Status" 0 "/api/domains/status"
    else
        track_test "Domain Status" 1 "/api/domains/status" "Domain status endpoint failed"
    fi
}

test_list_subdomains() {
    if api_call_with_retry "GET" "/api/domains/subdomains?parent_domain=datablox.co.za" "" 200 "List subdomains"; then
        track_test "List Subdomains" 0 "/api/domains/subdomains"
    else
        track_test "List Subdomains" 1 "/api/domains/subdomains" "List subdomains endpoint failed"
    fi
}

test_nextjs_deployment() {
    local nextjs_files='{
        "package.json": "{\"name\":\"'$TEST_APP_NAME'\",\"version\":\"1.0.0\",\"scripts\":{\"dev\":\"next dev\",\"build\":\"next build\",\"start\":\"next start -p $PORT\"},\"dependencies\":{\"next\":\"^13.5.0\",\"react\":\"^18.2.0\",\"react-dom\":\"^18.2.0\"}}",
        "pages/index.js": "export default function Home() { return (<div><h1>Test App</h1></div>); }"
    }'
    
    local subdomain_deploy_data='{
        "name": "'$TEST_APP_NAME'",
        "files": '$nextjs_files',
        "domain_config": {
            "subdomain": "'$TEST_SUBDOMAIN'",
            "parent_domain": "'$TEST_PARENT_DOMAIN'"
        }
    }'
    
    if api_call_with_retry "POST" "/api/deploy/nodejs-subdomain" "$subdomain_deploy_data" 200 "Deploy Next.js app" 1; then
        track_test "Deploy Next.js Subdomain" 0 "/api/deploy/nodejs-subdomain"
    else
        track_test "Deploy Next.js Subdomain" 1 "/api/deploy/nodejs-subdomain" "Next.js deployment failed"
    fi
}

# Register all tests
register_tests() {
    register_test "health_check" "test_health_check" "Basic health check"
    register_test "nginx_status" "test_nginx_status" "Nginx status endpoint"
    register_test "nginx_sites_enabled" "test_nginx_sites_enabled" "Nginx sites-enabled"
    register_test "comprehensive_sites_info" "test_comprehensive_sites_info" "Comprehensive sites info"
    register_test "sites_connectivity" "test_sites_connectivity" "Sites connectivity test"
    register_test "server_network_info" "test_server_network_info" "Server network info"
    register_test "nginx_domain_check" "test_nginx_domain_check" "Nginx domain check"
    register_test "domain_availability_subdomain" "test_domain_availability_subdomain" "Domain availability (subdomain)"
    register_test "domain_availability_simple" "test_domain_availability_simple" "Domain availability (simple)"
    register_test "subdomain_suggestions" "test_subdomain_suggestions" "Subdomain suggestions"
    register_test "domain_cleanup_candidates" "test_domain_cleanup_candidates" "Domain cleanup candidates"
    register_test "domain_status" "test_domain_status" "Domain status"
    register_test "list_subdomains" "test_list_subdomains" "List subdomains"
    register_test "nextjs_deployment" "test_nextjs_deployment" "Next.js deployment"
}

# Load failed tests from previous runs
load_failed_tests() {
    if [ -f "$FAILED_TESTS_FILE" ]; then
        print_info "Loading previously failed tests from $FAILED_TESTS_FILE"
        while IFS='|' read -r test_name endpoint error_msg timestamp; do
            if [ -n "$test_name" ]; then
                FAILED_TEST_DETAILS+=("$test_name|$endpoint|$error_msg|$timestamp")
            fi
        done < "$FAILED_TESTS_FILE"
    fi
}

# Run specific test by name
run_single_test() {
    local test_name="$1"
    
    if [ -z "${TEST_FUNCTIONS[$test_name]}" ]; then
        print_error "Test '$test_name' not found"
        list_available_tests
        return 1
    fi
    
    print_section "Running single test: ${TEST_DESCRIPTIONS[$test_name]}"
    ${TEST_FUNCTIONS[$test_name]}
}

# Run only failed tests
run_failed_tests() {
    if [ ${#FAILED_TEST_DETAILS[@]} -eq 0 ]; then
        print_info "No previously failed tests found"
        return 0
    fi
    
    print_section "Re-running ${#FAILED_TEST_DETAILS[@]} previously failed tests"
    
    local failed_test_names=()
    for detail in "${FAILED_TEST_DETAILS[@]}"; do
        IFS='|' read -r test_name endpoint error_msg timestamp <<< "$detail"
        failed_test_names+=("$test_name")
    done
    
    # Remove duplicates and run each failed test
    local unique_tests=($(printf '%s\n' "${failed_test_names[@]}" | sort -u))
    
    for test_name in "${unique_tests[@]}"; do
        # Find the test function key that matches this test name
        for key in "${!TEST_DESCRIPTIONS[@]}"; do
            if [[ "${TEST_DESCRIPTIONS[$key]}" =~ "$test_name" ]] || [[ "$key" =~ "$test_name" ]]; then
                run_single_test "$key"
                break
            fi
        done
    done
}

# Interactive test selection
run_interactive_tests() {
    print_section "Interactive Test Selection"
    
    echo "Available tests:"
    local i=1
    local test_keys=()
    for key in "${!TEST_DESCRIPTIONS[@]}"; do
        echo "  $i. ${TEST_DESCRIPTIONS[$key]}"
        test_keys+=("$key")
        i=$((i + 1))
    done
    
    echo ""
    echo "Enter test numbers (comma-separated) or 'all' for all tests:"
    read -r selection
    
    if [ "$selection" = "all" ]; then
        run_all_tests
        return
    fi
    
    # Parse comma-separated numbers
    IFS=',' read -ra selected_nums <<< "$selection"
    for num in "${selected_nums[@]}"; do
        num=$(echo "$num" | tr -d '[:space:]')  # Remove whitespace
        if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "${#test_keys[@]}" ]; then
            local test_key="${test_keys[$((num - 1))]}"
            run_single_test "$test_key"
        else
            print_warning "Invalid selection: $num"
        fi
    done
}

# List available tests
list_available_tests() {
    echo "Available tests:"
    for key in "${!TEST_DESCRIPTIONS[@]}"; do
        echo "  $key: ${TEST_DESCRIPTIONS[$key]}"
    done
}

# Run all tests (grouped by section)
run_all_tests() {
    print_section "Running all tests"
    
    # Basic tests
    test_health_check
    
    # Nginx tests
    print_section "NGINX ENDPOINT TESTS"
    test_nginx_status
    test_nginx_sites_enabled
    test_comprehensive_sites_info
    test_sites_connectivity
    test_server_network_info
    test_nginx_domain_check
    
    # Domain tests
    print_section "DOMAIN ENDPOINT TESTS"
    test_domain_availability_subdomain
    test_domain_availability_simple
    test_subdomain_suggestions
    test_domain_cleanup_candidates
    test_domain_status
    test_list_subdomains
    
    # Deployment tests
    print_section "DEPLOYMENT TESTS"
    test_nextjs_deployment
}

# Show failed tests summary
show_failed_tests() {
    if [ ${#FAILED_TEST_DETAILS[@]} -eq 0 ]; then
        print_info "No failed tests found"
        return
    fi
    
    print_section "Failed Tests Summary"
    echo "Total failed tests: ${#FAILED_TEST_DETAILS[@]}"
    echo ""
    
    for detail in "${FAILED_TEST_DETAILS[@]}"; do
        IFS='|' read -r test_name endpoint error_msg timestamp <<< "$detail"
        echo "❌ $test_name"
        echo "   Endpoint: $endpoint"
        echo "   Error: $error_msg"
        echo "   Time: $timestamp"
        echo ""
    done
}

# Print test summary
print_test_summary() {
    echo ""
    echo "=================================================="
    echo "              TEST SUMMARY"
    echo "=================================================="
    echo "Total Tests:  $TOTAL_TESTS"
    echo "Passed:       $PASSED_TESTS"
    echo "Failed:       $FAILED_TESTS"
    if [ $TOTAL_TESTS -gt 0 ]; then
        echo "Success Rate: $(( (PASSED_TESTS * 100) / TOTAL_TESTS ))%"
    fi
    echo "=================================================="
    
    echo ""
    echo "Detailed Results:"
    for result in "${TEST_RESULTS[@]}"; do
        echo "$result"
    done
    
    if [ $FAILED_TESTS -gt 0 ]; then
        echo ""
        print_warning "To re-run only failed tests: $0 --failed"
        print_info "To run specific test: $0 --test <test_name>"
        print_info "To run interactively: $0 --interactive"
    fi
}

# Check service health
check_service() {
    print_section "SERVICE HEALTH CHECK"
    
    if api_call "GET" "/api/health" "" 200 "Health check"; then
        print_success "API service is running"
        return 0
    else
        print_error "API is not running on ${BASE_URL}"
        return 1
    fi
}

# Main execution
main() {
    echo "=================================================="
    echo " ENHANCED Hosting Manager API Test Suite"
    echo "    (With Retry and Failed Test Management)"
    echo "=================================================="
    echo "Test Configuration:"
    echo "  API URL:           $BASE_URL"
    echo "  Run Mode:          $RUN_MODE"
    echo "  Retry Count:       $RETRY_COUNT"
    echo "  Test Timestamp:    $TEST_TIMESTAMP"
    echo "=================================================="
    
    # Check prerequisites
    if ! command -v curl &> /dev/null; then
        print_error "curl is required but not installed"
        exit 1
    fi
    
    # Initialize
    register_tests
    load_failed_tests
    
    # Service health check (except for failed-only mode)
    if [ "$RUN_MODE" != "failed" ]; then
        check_service || {
            print_error "API service is not available"
            exit 1
        }
    fi
    
    # Run tests based on mode
    case $RUN_MODE in
        "all")
            run_all_tests
            ;;
        "failed")
            run_failed_tests
            ;;
        "interactive")
            run_interactive_tests
            ;;
        "single")
            if [ -n "$SINGLE_TEST" ]; then
                run_single_test "$SINGLE_TEST"
            else
                print_error "No test specified for single mode"
                list_available_tests
                exit 1
            fi
            ;;
        "show-failed")
            show_failed_tests
            exit 0
            ;;
    esac
    
    # Print summary
    print_test_summary
    
    # Exit with proper code
    exit $FAILED_TESTS
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            echo "Enhanced Hosting Manager API Test Script with Retry Functionality"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --host HOST          API host (default: $API_HOST)"
            echo "  --port PORT          API port (default: $API_PORT)"
            echo "  --failed             Run only previously failed tests"
            echo "  --test TEST_NAME     Run a specific test"
            echo "  --interactive        Interactive test selection"
            echo "  --retry COUNT        Number of retries (default: $RETRY_COUNT)"
            echo "  --delay SECONDS      Retry delay (default: $RETRY_DELAY)"
            echo "  --show-failed        Show previously failed tests"
            echo "  --list-tests         List available tests"
            echo ""
            echo "Examples:"
            echo "  $0                           # Run all tests"
            echo "  $0 --failed                  # Re-run only failed tests"
            echo "  $0 --test nginx_status       # Run specific test"
            echo "  $0 --interactive             # Interactive mode"
            echo "  $0 --retry 5                 # Retry failed tests 5 times"
            exit 0
            ;;
        --host)
            API_HOST="$2"
            shift 2
            ;;
        --port)
            API_PORT="$2"
            shift 2
            ;;
        --failed)
            RUN_MODE="failed"
            shift
            ;;
        --test)
            RUN_MODE="single"
            SINGLE_TEST="$2"
            shift 2
            ;;
        --interactive)
            RUN_MODE="interactive"
            shift
            ;;
        --retry)
            RETRY_COUNT="$2"
            shift 2
            ;;
        --delay)
            RETRY_DELAY="$2"
            shift 2
            ;;
        --show-failed)
            RUN_MODE="show-failed"
            shift
            ;;
        --list-tests)
            register_tests
            list_available_tests
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

BASE_URL="http://${API_HOST}:${API_PORT}"

# Run main test suite
main