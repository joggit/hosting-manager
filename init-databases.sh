#!/bin/bash
# init-hosting-database.sh - Database initialization script for Hosting Manager
# Usage: ./init-hosting-database.sh [--force] [--db-path /path/to/database]

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Configuration
FORCE_RECREATE=false
DB_PATH=""
DEFAULT_DB_PATHS=(
    "/tmp/hosting/hosting.db"
    "/opt/hosting-manager/hosting.db"
    "/var/lib/hosting-manager/hosting.db"
    "./hosting.db"
)

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --force)
            FORCE_RECREATE=true
            shift
            ;;
        --db-path)
            DB_PATH="$2"
            shift 2
            ;;
        -h|--help)
            echo "Hosting Manager Database Initialization Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --force                 Force recreate tables (destructive)"
            echo "  --db-path PATH          Specify database path"
            echo "  -h, --help             Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                     # Auto-detect database location"
            echo "  $0 --db-path /custom/path/hosting.db"
            echo "  $0 --force             # Recreate all tables"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Auto-detect database path if not provided
detect_database() {
    print_info "Auto-detecting database location..."
    
    if [ -n "$DB_PATH" ] && [ -f "$DB_PATH" ]; then
        print_success "Using specified database: $DB_PATH"
        return 0
    fi
    
    for path in "${DEFAULT_DB_PATHS[@]}"; do
        if [ -f "$path" ]; then
            DB_PATH="$path"
            print_success "Found database: $DB_PATH"
            return 0
        fi
    done
    
    # If no database found, create in default location
    DB_PATH="/tmp/hosting/hosting.db"
    DB_DIR=$(dirname "$DB_PATH")
    
    print_warning "No existing database found. Creating new database: $DB_PATH"
    mkdir -p "$DB_DIR"
    touch "$DB_PATH"
    chmod 664 "$DB_PATH"
    
    return 0
}

# Check if SQLite3 is available
check_sqlite() {
    if ! command -v sqlite3 &> /dev/null; then
        print_error "sqlite3 is not installed. Installing..."
        if command -v apt &> /dev/null; then
            apt update && apt install -y sqlite3
        elif command -v yum &> /dev/null; then
            yum install -y sqlite
        else
            print_error "Cannot install sqlite3. Please install manually."
            exit 1
        fi
    fi
    print_success "SQLite3 is available"
}

# Backup existing database
backup_database() {
    if [ -f "$DB_PATH" ]; then
        local backup_path="${DB_PATH}.backup.$(date +%Y%m%d_%H%M%S)"
        print_info "Creating backup: $backup_path"
        cp "$DB_PATH" "$backup_path"
        print_success "Database backed up"
    fi
}

# Check table existence
table_exists() {
    local table_name="$1"
    local result=$(sqlite3 "$DB_PATH" "SELECT name FROM sqlite_master WHERE type='table' AND name='$table_name';")
    [ -n "$result" ]
}

# Create all core tables if they don't exist
create_core_tables() {
    print_info "Creating core database tables..."
    
    # Create domains table
    if ! table_exists "domains"; then
        print_info "Creating domains table..."
        sqlite3 "$DB_PATH" << 'EOF'
CREATE TABLE domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_name TEXT UNIQUE NOT NULL,
    port INTEGER NOT NULL,
    site_type TEXT DEFAULT 'static',
    ssl_enabled BOOLEAN DEFAULT 0,
    status TEXT DEFAULT 'active',
    process_manager TEXT DEFAULT 'systemd',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    parent_domain TEXT,
    app_name TEXT,
    deployment_status TEXT DEFAULT 'active',
    nginx_config_path TEXT,
    ssl_certificate_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_domains_name ON domains(domain_name);
CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status);
EOF
        print_success "domains table created"
    else
        print_info "domains table already exists"
    fi
    
    # Create processes table
    if ! table_exists "processes"; then
        print_info "Creating processes table..."
        sqlite3 "$DB_PATH" << 'EOF'
CREATE TABLE processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    domain_name TEXT,
    port INTEGER,
    pid INTEGER,
    status TEXT DEFAULT 'stopped',
    process_manager TEXT DEFAULT 'systemd',
    start_command TEXT,
    cwd TEXT,
    memory_usage INTEGER DEFAULT 0,
    cpu_usage REAL DEFAULT 0.0,
    restart_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_name) REFERENCES domains (domain_name)
);

CREATE INDEX IF NOT EXISTS idx_processes_name ON processes(name);
CREATE INDEX IF NOT EXISTS idx_processes_status ON processes(status);
EOF
        print_success "processes table created"
    else
        print_info "processes table already exists"
    fi
    
    # Create deployment_logs table
    if ! table_exists "deployment_logs"; then
        print_info "Creating deployment_logs table..."
        sqlite3 "$DB_PATH" << 'EOF'
CREATE TABLE deployment_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_name TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_logs_domain ON deployment_logs(domain_name);
EOF
        print_success "deployment_logs table created"
    else
        print_info "deployment_logs table already exists"
    fi
    
    # Create health_checks table
    if ! table_exists "health_checks"; then
        print_info "Creating health_checks table..."
        sqlite3 "$DB_PATH" << 'EOF'
CREATE TABLE health_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_name TEXT NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER,
    response_time REAL,
    status TEXT NOT NULL,
    error_message TEXT,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_health_domain ON health_checks(domain_name);
EOF
        print_success "health_checks table created"
    else
        print_info "health_checks table already exists"
    fi
}

# Create parent_domains table
create_parent_domains_table() {
    print_info "Creating parent_domains table..."
    
    if table_exists "parent_domains" && [ "$FORCE_RECREATE" = false ]; then
        print_warning "parent_domains table already exists. Use --force to recreate."
        return 0
    fi
    
    if [ "$FORCE_RECREATE" = true ]; then
        print_warning "Dropping existing parent_domains table..."
        sqlite3 "$DB_PATH" "DROP TABLE IF EXISTS parent_domains;"
    fi
    
    sqlite3 "$DB_PATH" << 'EOF'
CREATE TABLE parent_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_name TEXT UNIQUE NOT NULL,
    port_range_start INTEGER NOT NULL DEFAULT 3001,
    port_range_end INTEGER NOT NULL DEFAULT 3100,
    ssl_enabled BOOLEAN DEFAULT 1,
    description TEXT,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_parent_domains_name ON parent_domains(domain_name);
CREATE INDEX IF NOT EXISTS idx_parent_domains_status ON parent_domains(status);
EOF

    print_success "parent_domains table created"
}

# Update existing domains table if needed
update_domains_table() {
    print_info "Checking domains table structure..."
    
    # Get current schema
    local schema=$(sqlite3 "$DB_PATH" ".schema domains")
    
    # Add missing columns if they don't exist
    local columns_to_add=(
        "parent_domain TEXT"
        "app_name TEXT"
        "deployment_status TEXT DEFAULT 'active'"
        "nginx_config_path TEXT"
        "ssl_certificate_id TEXT"
    )
    
    for column in "${columns_to_add[@]}"; do
        local column_name=$(echo "$column" | cut -d' ' -f1)
        if ! echo "$schema" | grep -q "$column_name"; then
            print_info "Adding column: $column_name"
            sqlite3 "$DB_PATH" "ALTER TABLE domains ADD COLUMN $column;" 2>/dev/null || print_warning "Column $column_name may already exist"
        fi
    done
    
    print_success "domains table structure updated"
}

# Insert default parent domains
insert_default_domains() {
    print_info "Inserting default parent domains..."
    
    sqlite3 "$DB_PATH" << 'EOF'
INSERT OR IGNORE INTO parent_domains 
(domain_name, port_range_start, port_range_end, description, ssl_enabled, status) 
VALUES 
('smartwave.co.za', 3001, 3100, 'SmartWave Technology Domain', 1, 'active'),
('datablox.co.za', 3101, 3200, 'DataBlox Analytics Domain', 1, 'active'),
('mondaycafe.co.za', 3201, 3300, 'Monday Cafe Domain', 1, 'active');
EOF

    local count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM parent_domains;")
    print_success "Default parent domains ready (total: $count)"
}

# Update existing subdomains with parent references
update_subdomain_references() {
    print_info "Updating subdomain parent references..."
    
    sqlite3 "$DB_PATH" << 'EOF'
UPDATE domains SET parent_domain = 'smartwave.co.za' 
WHERE domain_name LIKE '%.smartwave.co.za' AND domain_name != 'smartwave.co.za';

UPDATE domains SET parent_domain = 'datablox.co.za' 
WHERE domain_name LIKE '%.datablox.co.za' AND domain_name != 'datablox.co.za';

UPDATE domains SET parent_domain = 'mondaycafe.co.za' 
WHERE domain_name LIKE '%.mondaycafe.co.za' AND domain_name != 'mondaycafe.co.za';
EOF

    print_success "Subdomain references updated"
}

# Clean up old data
cleanup_old_data() {
    print_info "Cleaning up old/removed domains..."
    
    # Remove domains marked as 'removed'
    local removed_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM domains WHERE status = 'removed';" 2>/dev/null || echo "0")
    if [ "$removed_count" -gt 0 ]; then
        print_warning "Removing $removed_count old domains marked as 'removed'"
        sqlite3 "$DB_PATH" "DELETE FROM domains WHERE status = 'removed';"
    fi
    
    print_success "Cleanup completed"
}

# Verify database integrity
verify_database() {
    print_info "Verifying database integrity..."
    
    # Check database integrity
    local integrity=$(sqlite3 "$DB_PATH" "PRAGMA integrity_check;")
    if [ "$integrity" != "ok" ]; then
        print_error "Database integrity check failed: $integrity"
        return 1
    fi
    
    # Verify table structure
    local tables=$(sqlite3 "$DB_PATH" ".tables")
    local required_tables=("domains" "parent_domains" "deployment_logs" "health_checks" "processes")
    
    for table in "${required_tables[@]}"; do
        if ! echo "$tables" | grep -q "$table"; then
            print_warning "Missing table: $table"
        else
            local count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM $table;" 2>/dev/null || echo "0")
            print_info "Table $table: $count records"
        fi
    done
    
    print_success "Database verification completed"
}

# Show database summary
show_summary() {
    print_info "Database Summary:"
    echo "=================="
    echo "Database Path: $DB_PATH"
    echo "Database Size: $(du -h "$DB_PATH" | cut -f1)"
    echo ""
    
    # Parent domains summary
    echo "Parent Domains:"
    sqlite3 "$DB_PATH" -header -column \
        "SELECT domain_name, port_range_start, port_range_end, description 
         FROM parent_domains WHERE status='active';" 2>/dev/null || echo "No parent domains found"
    echo ""
    
    # Active domains summary
    echo "Active Subdomains:"
    sqlite3 "$DB_PATH" -header -column \
        "SELECT domain_name, port, site_type, parent_domain 
         FROM domains WHERE status='active' LIMIT 10;" 2>/dev/null || echo "No subdomains found"
    
    local total_domains=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM domains WHERE status='active';" 2>/dev/null || echo "0")
    echo "Total Active Domains: $total_domains"
    echo ""
}

# Set proper permissions
set_permissions() {
    print_info "Setting proper permissions..."
    
    # Ensure directory exists and has proper permissions
    local db_dir=$(dirname "$DB_PATH")
    mkdir -p "$db_dir"
    
    # Set ownership to www-data if it exists, otherwise root
    if id "www-data" &>/dev/null; then
        chown -R www-data:www-data "$db_dir" 2>/dev/null || print_warning "Could not set ownership to www-data"
        print_success "Set ownership to www-data"
    else
        print_warning "www-data user not found, keeping current ownership"
    fi
    
    # Set proper file permissions
    chmod 755 "$db_dir"
    chmod 664 "$DB_PATH"
    
    print_success "Permissions set"
}

# Main execution
main() {
    echo "=================================================="
    echo " Hosting Manager Database Initialization Script"
    echo "=================================================="
    echo ""
    
    # Check prerequisites
    check_sqlite
    
    # Detect or create database
    detect_database
    
    # Backup existing database if needed
    if [ "$FORCE_RECREATE" = true ]; then
        backup_database
    fi
    
    # Create all core tables first
    create_core_tables
    
    # Create/update database structure
    create_parent_domains_table
    update_domains_table
    
    # Populate with default data
    insert_default_domains
    update_subdomain_references
    
    # Cleanup and maintenance
    cleanup_old_data
    
    # Verify everything is working
    verify_database
    
    # Set proper permissions
    set_permissions
    
    # Show summary
    show_summary
    
    echo ""
    echo "=================================================="
    print_success "Database initialization completed successfully!"
    echo "=================================================="
    echo ""
    echo "Next steps:"
    echo "1. Test the API: curl http://localhost:5000/api/domains"
    echo "2. Copy this database to your server: scp $DB_PATH root@75.119.141.162:/tmp/hosting/"
    echo "3. Restart the hosting manager service"
    echo ""
}

# Run main function
main "$@"