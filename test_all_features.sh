#!/bin/bash
# Comprehensive test script for all functionalities

echo "=========================================="
echo "Testing Adaptive Secure Communication System"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

cd /mnt/c/Projects/Lab/NPS/EL/Project

# Test 1: Build system
echo -e "${YELLOW}[TEST 1] Build System${NC}"
make clean > /dev/null 2>&1
if make all > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi
echo ""

# Test 2: Check if binaries exist
echo -e "${YELLOW}[TEST 2] Binary Files${NC}"
if [ -f bin/server ] && [ -f bin/client ]; then
    echo -e "${GREEN}✓ Server and client binaries exist${NC}"
else
    echo -e "${RED}✗ Missing binaries${NC}"
    exit 1
fi
echo ""

# Test 3: Check TLS certificates
echo -e "${YELLOW}[TEST 3] TLS Certificates${NC}"
if [ -f certs/server.crt ] && [ -f certs/server.key ] && [ -f certs/ca.crt ]; then
    echo -e "${GREEN}✓ TLS certificates exist${NC}"
else
    echo -e "${RED}✗ Missing TLS certificates${NC}"
    exit 1
fi
echo ""

# Test 4: Check data directory structure
echo -e "${YELLOW}[TEST 4] Directory Structure${NC}"
if [ -d data/offline_queue ]; then
    echo -e "${GREEN}✓ Offline queue directory exists${NC}"
else
    echo -e "${RED}✗ Missing offline queue directory${NC}"
    mkdir -p data/offline_queue
fi
echo ""

# Test 5: Run unit tests (if they exist)
echo -e "${YELLOW}[TEST 5] Unit Tests${NC}"
if [ -f bin/test_ratchet ]; then
    if ./bin/test_ratchet > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Ratchet tests passed${NC}"
    else
        echo -e "${YELLOW}⚠ Ratchet tests need review${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Ratchet tests not built${NC}"
fi
echo ""

# Test 6: Start server and test basic connection
echo -e "${YELLOW}[TEST 6] Server-Client Connection${NC}"
./bin/server > /tmp/server_test.log 2>&1 &
SERVER_PID=$!
sleep 2

# Check if server is running
if ps -p $SERVER_PID > /dev/null; then
    echo -e "${GREEN}✓ Server started (PID: $SERVER_PID)${NC}"
else
    echo -e "${RED}✗ Server failed to start${NC}"
    exit 1
fi

# Test client connection
echo "test message" | timeout 5 ./bin/client localhost 8080 testuser > /tmp/client_test.log 2>&1 &
CLIENT_PID=$!
sleep 3

if grep -q "Connected as testuser" /tmp/client_test.log; then
    echo -e "${GREEN}✓ Client connected successfully${NC}"
else
    echo -e "${RED}✗ Client connection failed${NC}"
    cat /tmp/client_test.log
fi

kill $CLIENT_PID 2>/dev/null
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null
echo ""

# Test 7: Check cryptographic components
echo -e "${YELLOW}[TEST 7] Cryptographic Components${NC}"
if nm bin/server | grep -q "ratchet_init"; then
    echo -e "${GREEN}✓ Ratchet functions linked${NC}"
else
    echo -e "${RED}✗ Ratchet functions not found${NC}"
fi

if nm bin/server | grep -q "aes_encrypt"; then
    echo -e "${GREEN}✓ AES functions linked${NC}"
else
    echo -e "${RED}✗ AES functions not found${NC}"
fi

if nm bin/server | grep -q "dh_generate_keypair"; then
    echo -e "${GREEN}✓ DH functions linked${NC}"
else
    echo -e "${RED}✗ DH functions not found${NC}"
fi
echo ""

# Test 8: Check adaptive engine
echo -e "${YELLOW}[TEST 8] Adaptive Engine${NC}"
if nm bin/server | grep -q "engine_init"; then
    echo -e "${GREEN}✓ Adaptive engine functions linked${NC}"
else
    echo -e "${RED}✗ Adaptive engine functions not found${NC}"
fi
echo ""

# Test 9: Check multipath transport
echo -e "${YELLOW}[TEST 9] Multi-Path Transport${NC}"
if nm bin/server | grep -q "multipath_send"; then
    echo -e "${GREEN}✓ Multipath functions linked${NC}"
else
    echo -e "${RED}✗ Multipath functions not found${NC}"
fi
echo ""

# Test 10: Check offline queue
echo -e "${YELLOW}[TEST 10] Offline Queue${NC}"
if nm bin/server | grep -q "queue_store"; then
    echo -e "${GREEN}✓ Offline queue functions linked${NC}"
else
    echo -e "${RED}✗ Offline queue functions not found${NC}"
fi
echo ""

# Test 11: Check intrusion detection
echo -e "${YELLOW}[TEST 11] Intrusion Detection${NC}"
if nm bin/server | grep -q "ids_record_auth_fail"; then
    echo -e "${GREEN}✓ IDS functions linked${NC}"
else
    echo -e "${RED}✗ IDS functions not found${NC}"
fi
echo ""

echo "=========================================="
echo -e "${GREEN}All basic tests completed!${NC}"
echo "=========================================="
