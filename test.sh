#!/bin/bash

# Test script for HTTP Proxy Manager
# Validates syntax and basic functionality

set +e  # Don't exit on errors, we want to run all tests

echo "=================================="
echo "HTTP Proxy Manager - Test Suite"
echo "=================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0

print_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASSED++))
}

print_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((FAILED++))
}

print_info() {
    echo -e "${YELLOW}ℹ INFO${NC}: $1"
}

# Test 1: Check if install.sh exists
echo "Test 1: File existence check"
if [ -f "install.sh" ]; then
    print_pass "install.sh exists"
else
    print_fail "install.sh not found"
fi
echo ""

# Test 2: Check bash syntax
echo "Test 2: Bash syntax validation"
if bash -n install.sh 2>/dev/null; then
    print_pass "Bash syntax is valid"
else
    print_fail "Bash syntax errors detected"
    bash -n install.sh
fi
echo ""

# Test 3: Check shebang
echo "Test 3: Shebang validation"
if head -n 1 install.sh | grep -q "#!/bin/bash"; then
    print_pass "Correct shebang found"
else
    print_fail "Shebang missing or incorrect"
fi
echo ""

# Test 4: Check for required functions
echo "Test 4: Required functions check"
required_functions=(
    "main"
    "install_dependencies"
    "create_profile"
    "delete_profile"
    "show_connections"
    "generate_squid_config"
    "check_os_compatibility"
    "check_dependencies"
    "backup_profiles"
    "log_message"
)

for func in "${required_functions[@]}"; do
    if grep -q "^${func}()" install.sh || grep -q "^${func} ()" install.sh; then
        print_pass "Function '$func' found"
    else
        print_fail "Function '$func' not found"
    fi
done
echo ""

# Test 5: Check for version variable
echo "Test 5: Version tracking"
if grep -q "VERSION=" install.sh; then
    VERSION=$(grep "^VERSION=" install.sh | cut -d'"' -f2)
    print_pass "Version variable found: $VERSION"
else
    print_fail "Version variable not found"
fi
echo ""

# Test 6: Check for security features
echo "Test 6: Security features check"
security_checks=(
    "set -euo pipefail"
    "forwarded_for delete"
    "via off"
    "httpd_suppress_version_string on"
)

for check in "${security_checks[@]}"; do
    if grep -q "$check" install.sh; then
        print_pass "Security feature: '$check'"
    else
        print_fail "Security feature missing: '$check'"
    fi
done
echo ""

# Test 7: Check README.md
echo "Test 7: Documentation check"
if [ -f "README.md" ]; then
    print_pass "README.md exists"
    
    if grep -q "Troubleshooting" README.md; then
        print_pass "Troubleshooting section found"
    else
        print_fail "Troubleshooting section missing"
    fi
    
    if grep -q "Best Practices" README.md; then
        print_pass "Best Practices section found"
    else
        print_fail "Best Practices section missing"
    fi
else
    print_fail "README.md not found"
fi
echo ""

# Test 8: Check CHANGELOG.md
echo "Test 8: Changelog check"
if [ -f "CHANGELOG.md" ]; then
    print_pass "CHANGELOG.md exists"
    
    if grep -q "\[1.0.0\]" CHANGELOG.md; then
        print_pass "Version 1.0.0 documented"
    else
        print_fail "Version 1.0.0 not documented"
    fi
else
    print_fail "CHANGELOG.md not found"
fi
echo ""

# Test 9: Check for backup functionality
echo "Test 9: Backup functionality"
if grep -q "backup_profiles()" install.sh; then
    print_pass "Backup function implemented"
else
    print_fail "Backup function not found"
fi
echo ""

# Test 10: Check for logging
echo "Test 10: Logging functionality"
if grep -q "log_message" install.sh && grep -q "LOG_FILE=" install.sh; then
    print_pass "Logging system implemented"
else
    print_fail "Logging system not found"
fi
echo ""

# Test 11: Check for performance optimizations
echo "Test 11: Performance optimizations"
perf_features=(
    "dns_nameservers"
    "connect_timeout"
    "client_lifetime"
    "pconn_timeout"
)

for feature in "${perf_features[@]}"; do
    if grep -q "$feature" install.sh; then
        print_pass "Performance feature: '$feature'"
    else
        print_fail "Performance feature missing: '$feature'"
    fi
done
echo ""

# Test 12: Check file permissions recommendation
echo "Test 12: File attributes"
if [ -x "install.sh" ]; then
    print_pass "install.sh is executable"
else
    print_info "install.sh should be executable (chmod +x install.sh)"
fi
echo ""

# Summary
echo "=================================="
echo "Test Summary"
echo "=================================="
echo -e "${GREEN}Passed${NC}: $PASSED"
echo -e "${RED}Failed${NC}: $FAILED"
echo "Total: $((PASSED + FAILED))"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
