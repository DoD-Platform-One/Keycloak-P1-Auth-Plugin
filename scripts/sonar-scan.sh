#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}=========================================${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Function to run main code scan
run_main_scan() {
    print_header "Running Code Quality Scan"
    
    if [ -z "$SONAR_LOGIN" ]; then
        print_error "SONAR_LOGIN not set"
        echo "Run: export SONAR_LOGIN=your-token"
        return 1
    fi
    
    echo "Step 1: Clean build with tests and coverage..."
    ./gradlew clean test jacocoTestReport || {
        print_error "Build failed"
        return 1
    }
    
    echo ""
    echo "Step 2: Checking coverage reports..."
    local missing_reports=0
    for report in p1-keycloak-plugin/build/jacoco/test.xml \
                  quarkus-ext-routing/deployment/build/jacoco/test.xml \
                  quarkus-ext-routing/runtime/build/jacoco/test.xml; do
        if [ -f "$report" ]; then
            print_success "Found: $report"
        else
            print_warning "Missing: $report"
            missing_reports=$((missing_reports + 1))
        fi
    done
    
    echo ""
    echo "Step 3: Running SonarQube scan..."
    sonar-scanner -Dproject.settings=sonar-project-dev.properties
    
    print_success "Code quality scan complete: http://localhost:9000/dashboard?id=keycloak-plugin"
}

# Function to run dependency check scan
run_dependency_scan() {
    print_header "Running Dependency Check Scan"
    
    # Check database
    if [ ! -f ~/.gradle/dependency-check-data/11.0/odc.mv.db ]; then
        print_error "No dependency database found!"
        echo "Run: $0 update"
        return 1
    fi
    
    DB_SIZE=$(stat -c%s ~/.gradle/dependency-check-data/11.0/odc.mv.db)
    if [ $DB_SIZE -lt 300000000 ]; then
        print_warning "Database may be incomplete ($(ls -lh ~/.gradle/dependency-check-data/11.0/odc.mv.db | awk '{print $5}'))"
        echo "Consider running: $0 update"
    fi
    
    echo "Running dependency check..."
    
    # Stop any existing daemons first
    ./gradlew --stop 2>/dev/null || true
    
    # Set data directory
    DC_DATA_DIR="${HOME}/.gradle/dependency-check-data"
    
    # Use fast mode if requested
    if [ "$1" = "fast" ]; then
        echo "(Using fast offline mode)"
        ./gradlew --no-daemon --offline \
            -Dorg.owasp.dependencycheck.data.directory="$DC_DATA_DIR" \
            -Dnvd.api.key="$NVD_API_KEY" \
            dependencyCheckAnalyze || {
            print_warning "Dependency check failed"
        }
    else
        ./gradlew --no-daemon \
            -Dorg.owasp.dependencycheck.data.directory="$DC_DATA_DIR" \
            -Dnvd.api.key="$NVD_API_KEY" \
            dependencyCheckAnalyze || {
            print_warning "Dependency check failed"
        }
    fi
    
    # Check for reports and run SonarQube scan if found
    local found_report=false
    for report in build/reports/dependency-check-report.json \
                  p1-keycloak-plugin/build/reports/dependency-check-report.json; do
        if [ -f "$report" ]; then
            found_report=true
            break
        fi
    done
    
    if [ "$found_report" = true ]; then
        if [ -z "$SONAR_LOGIN_DEPENDENCY_CHECK" ]; then
            export SONAR_LOGIN_DEPENDENCY_CHECK=$SONAR_LOGIN
        fi
        
        echo "Running SonarQube scan for dependency check..."
        sonar-scanner -Dproject.settings=sonar-project-dependency-check-dev.properties
        print_success "Dependency scan complete: http://localhost:9000/dashboard?id=keycloak-plugin-dependency-check"
    else
        print_warning "No dependency reports found, skipping SonarQube scan"
    fi
}

# Function to update dependency database
update_database() {
    print_header "Updating Dependency Database"
    
    echo "This updates the vulnerability database (~400MB when complete)"
    echo ""
    
    if [ -n "$NVD_API_KEY" ]; then
        print_success "Using NVD API key (10-20 minutes)"
    else
        print_warning "No NVD_API_KEY set - this will take 2-4 HOURS"
        echo ""
        echo "Get a FREE API key (instant) at:"
        echo "https://nvd.nist.gov/developers/request-an-api-key"
        echo ""
        read -p "Continue without API key? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Get an API key first: export NVD_API_KEY=your-key"
            exit 1
        fi
    fi
    
    # Check current database
    if [ -f ~/.gradle/dependency-check-data/11.0/odc.mv.db ]; then
        echo "Current database: $(ls -lh ~/.gradle/dependency-check-data/11.0/odc.mv.db | awk '{print $5}')"
    else
        echo "No existing database"
    fi
    
    # Remove lock files
    rm -f ~/.gradle/dependency-check-data/11.0/*.lock
    
    echo ""
    echo "Updating database..."
    DC_DATA_DIR="${HOME}/.gradle/dependency-check-data"
    
    timeout 10m ./gradlew --no-daemon \
        -Dorg.owasp.dependencycheck.data.directory="$DC_DATA_DIR" \
        -Dnvd.api.key="$NVD_API_KEY" \
        dependencyCheckUpdate || {
        print_error "Database update failed or timed out"
        return 1
    }
    
    # Check result
    if [ -f ~/.gradle/dependency-check-data/11.0/odc.mv.db ]; then
        FINAL_SIZE=$(ls -lh ~/.gradle/dependency-check-data/11.0/odc.mv.db | awk '{print $5}')
        echo "Final size: $FINAL_SIZE"
        
        SIZE_BYTES=$(stat -c%s ~/.gradle/dependency-check-data/11.0/odc.mv.db)
        if [ $SIZE_BYTES -gt 300000000 ]; then
            print_success "Database update successful!"
        else
            print_warning "Database may be incomplete (expected ~400-500MB)"
        fi
    else
        print_error "Database update failed"
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  code        Run code quality scan with coverage"
    echo "  deps        Run dependency vulnerability scan"
    echo "  deps-fast   Run fast dependency scan (offline)"
    echo "  all         Run both code and dependency scans (default)"
    echo "  update      Update dependency check database"
    echo "  help        Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  SONAR_LOGIN                  Token for main SonarQube project"
    echo "  SONAR_LOGIN_DEPENDENCY_CHECK Token for dependency check project"
    echo "  NVD_API_KEY                  API key for fast database updates"
    echo ""
    echo "Examples:"
    echo "  $0 code                     # Just code quality"
    echo "  $0 deps                     # Just dependencies"
    echo "  $0 deps-fast                # Fast offline dependency check"
    echo "  $0 all                      # Everything"
    echo "  $0 update                   # Update vulnerability database"
}

# Main script logic
case "${1:-all}" in
    code|main)
        run_main_scan
        ;;
    deps|dep|dependency)
        run_dependency_scan
        ;;
    deps-fast|dep-fast)
        run_dependency_scan "fast"
        ;;
    all|both)
        run_main_scan
        echo ""
        run_dependency_scan
        ;;
    update|update-db)
        update_database
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        print_error "Unknown command: $1"
        show_usage
        exit 1
        ;;
esac