# Makefile for Secure Multi-Client Chat Application

# Detect OS
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
    SHELL := cmd.exe
    RM := del /Q /F
    RMDIR := rmdir /S /Q
    MKDIR := mkdir
    PATHSEP := \\
    EXE_EXT := .exe
    # Windows-specific flags
    LDFLAGS_PLATFORM := -lws2_32
    CFLAGS_PLATFORM := 
else
    DETECTED_OS := $(shell uname -s)
    RM := rm -f
    RMDIR := rm -rf
    MKDIR := mkdir -p
    PATHSEP := /
    EXE_EXT :=
    # Unix-specific flags
    LDFLAGS_PLATFORM :=
    CFLAGS_PLATFORM :=
endif

CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -std=c11 -g \
          -I./include \
          $(CFLAGS_PLATFORM) \
          $(shell pkg-config --cflags openssl 2>nul || echo -I/usr/include)
LDFLAGS = $(shell pkg-config --libs openssl 2>nul || echo -lssl -lcrypto) \
          -lpthread $(LDFLAGS_PLATFORM)

# Source file groups
SRC_COMMON = src/crypto/rsa_utils.c src/crypto/aes_utils.c \
             src/crypto/dh_exchange.c src/crypto/crypto_common.c \
             src/crypto/ratchet.c \
             src/tls/tls_server.c src/tls/tls_client.c \
             src/engine/adaptive_engine.c src/engine/metrics_collector.c \
             src/transport/multipath.c src/transport/offline_queue.c \
             src/transport/priority_queue.c \
             src/security/intrusion.c \
             src/net/socket_utils.c src/net/dns_resolver.c \
             src/net/udp_notify.c src/net/message_utils.c

SRC_SERVER = src/server/server.c src/server/client_handler.c \
             src/server/room_manager.c src/server/auth_manager.c

SRC_CLIENT = src/client/client.c src/client/input_handler.c \
             src/client/display.c

# Phase 1 - Basic TCP only (no crypto/TLS dependencies)
SRC_PHASE1_COMMON = src/net/socket_utils.c src/net/message_utils.c
SRC_PHASE1_SERVER = src/server/server.c  
SRC_PHASE1_CLIENT = src/client/client.c

# Object files
OBJ_COMMON = $(SRC_COMMON:.c=.o)
OBJ_SERVER = $(SRC_SERVER:.c=.o)
OBJ_CLIENT = $(SRC_CLIENT:.c=.o)

OBJ_PHASE1_COMMON = $(SRC_PHASE1_COMMON:.c=.o)
OBJ_PHASE1_SERVER = $(SRC_PHASE1_SERVER:.c=.o)
OBJ_PHASE1_CLIENT = $(SRC_PHASE1_CLIENT:.c=.o)

# Default target
all: bin server client certs

# Phase 1 targets (no crypto/TLS dependencies)
phase1: bin phase1-server phase1-client

phase1-server: bin bin/server_phase1

bin/server_phase1: $(OBJ_PHASE1_SERVER) $(OBJ_PHASE1_COMMON)
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

phase1-client: bin bin/client_phase1  

bin/client_phase1: $(OBJ_PHASE1_CLIENT) $(OBJ_PHASE1_COMMON)
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

# Create bin directory
bin:
	mkdir -p bin

# Build server
server: bin bin/server

bin/server: $(OBJ_SERVER) $(OBJ_COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Build client  
client: bin bin/client

bin/client: $(OBJ_CLIENT) $(OBJ_COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Generate TLS certificates
certs:
	mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -keyout certs/server.key \
	  -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"
	cp certs/server.crt certs/ca.crt

# Build tests
tests: bin bin/test_ratchet bin/test_crypto bin/test_adaptive bin/test_multipath

bin/test_ratchet: tests/test_ratchet.c $(OBJ_COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bin/test_crypto: tests/test_crypto.c $(OBJ_COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bin/test_adaptive: tests/test_adaptive.c $(OBJ_COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bin/test_multipath: tests/test_multipath.c $(OBJ_COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Generic rule for object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJ_COMMON) $(OBJ_SERVER) $(OBJ_CLIENT)
	rm -f $(OBJ_PHASE1_COMMON) $(OBJ_PHASE1_SERVER) $(OBJ_PHASE1_CLIENT)
	rm -f bin/server bin/client bin/server_phase1 bin/client_phase1 bin/test_*

# Clean everything including certificates
clean-all: clean
	rm -rf certs/*

# Install dependencies (for Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y gcc make libssl-dev pkg-config

# Run tests
test: tests
	@echo "\n=== Running Test Suite ===\n"
	./bin/test_ratchet
	./bin/test_crypto
	./bin/test_adaptive
	./bin/test_multipath
	@echo "\n=== All Tests Complete ===\n"

# Debug build
debug: CFLAGS += -DDEBUG -O0
debug: all

# Release build
release: CFLAGS += -O2 -DNDEBUG
release: all

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Build server and client (default)"
	@echo "  phase1       - Build Phase 1 TCP echo server and client"
	@echo "  server       - Build server only"
	@echo "  client       - Build client only"
	@echo "  tests        - Build test executables"
	@echo "  certs        - Generate TLS certificates"
	@echo "  clean        - Remove build artifacts"
	@echo "  clean-all    - Remove build artifacts and certificates"
	@echo "  install-deps - Install system dependencies"
	@echo "  test         - Build and run tests"
	@echo "  debug        - Build with debug symbols and no optimization"
	@echo "  release      - Build optimized release version"
	@echo "  help         - Show this help message"

.PHONY: all server client tests certs clean clean-all install-deps test debug release help phase1 phase1-server phase1-client