CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -g -I./include \
          -D_POSIX_C_SOURCE=200809L \
          $(shell pkg-config --cflags openssl)
LDFLAGS = $(shell pkg-config --libs openssl) -lpthread -lrt

SRC_COMMON = \
    src/crypto/ratchet.c \
    src/crypto/rsa_utils.c \
    src/crypto/aes_utils.c \
    src/crypto/crypto_common.c \
    src/tls/tls_server.c \
    src/tls/tls_client.c \
    src/engine/adaptive_engine.c \
    src/engine/metrics_collector.c \
    src/transport/multipath.c \
    src/transport/offline_queue.c \
    src/transport/priority_queue.c \
    src/security/intrusion.c \
    src/net/socket_utils.c \
    src/net/message_utils.c \
    src/net/dns_resolver.c \
    src/net/udp_notify.c

SRC_SERVER = \
    src/server/server.c \
    src/server/client_handler.c \
    src/server/room_manager.c \
    src/server/auth_manager.c

SRC_CLIENT = \
    src/client/client.c \
    src/client/input_handler.c \
    src/client/display.c

all: dirs server client

dirs:
	mkdir -p bin data/offline_queue data/keys

server: $(SRC_SERVER) $(SRC_COMMON)
	$(CC) $(CFLAGS) -o bin/server $^ $(LDFLAGS)

client: $(SRC_CLIENT) $(SRC_COMMON)
	$(CC) $(CFLAGS) -o bin/client $^ $(LDFLAGS)

gtk-client: src/client/gtk_client.c $(SRC_CLIENT) $(SRC_COMMON)
	$(CC) $(CFLAGS) -DHAVE_GTK \
	    $(shell pkg-config --cflags gtk+-3.0) \
	    -o bin/client_gtk $^ \
	    $(LDFLAGS) $(shell pkg-config --libs gtk+-3.0)

certs:
	mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -keyout certs/server.key \
	    -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"
	cp certs/server.crt certs/ca.crt

tests: test_crypto test_ratchet test_adaptive test_multipath test_tls test_ids

test_crypto: tests/test_crypto.c $(SRC_COMMON)
	$(CC) $(CFLAGS) -o bin/test_crypto $^ $(LDFLAGS)
	./bin/test_crypto

test_ratchet: tests/test_ratchet.c \
    src/crypto/ratchet.c src/crypto/crypto_common.c \
    src/crypto/rsa_utils.c $(SRC_COMMON)
	$(CC) $(CFLAGS) -o bin/test_ratchet tests/test_ratchet.c $(SRC_COMMON) $(LDFLAGS)
	./bin/test_ratchet

test_adaptive: tests/test_adaptive.c \
    src/engine/adaptive_engine.c src/engine/metrics_collector.c
	$(CC) $(CFLAGS) -o bin/test_adaptive \
	    tests/test_adaptive.c \
	    src/engine/adaptive_engine.c \
	    src/engine/metrics_collector.c \
	    $(LDFLAGS)
	./bin/test_adaptive

test_multipath: tests/test_multipath.c src/transport/multipath.c \
    src/tls/tls_client.c src/net/udp_notify.c
	$(CC) $(CFLAGS) -o bin/test_multipath \
	    tests/test_multipath.c \
	    src/transport/multipath.c \
	    src/tls/tls_client.c \
	    src/tls/tls_server.c \
	    src/net/udp_notify.c \
	    $(LDFLAGS)
	./bin/test_multipath

test_tls: tests/test_tls.c src/tls/tls_client.c src/tls/tls_server.c
	$(CC) $(CFLAGS) -o bin/test_tls \
	    tests/test_tls.c \
	    src/tls/tls_client.c \
	    src/tls/tls_server.c \
	    $(LDFLAGS)
	./bin/test_tls

test_ids: tests/test_ids.c src/security/intrusion.c \
    src/engine/metrics_collector.c
	$(CC) $(CFLAGS) -o bin/test_ids \
	    tests/test_ids.c \
	    src/security/intrusion.c \
	    src/engine/metrics_collector.c \
	    $(LDFLAGS)
	./bin/test_ids

clean:
	rm -f bin/*

distclean: clean
	rm -f certs/* data/keys/*
	find data/offline_queue -type f -delete 2>/dev/null || true

.PHONY: all dirs server client gtk-client certs tests \
        test_crypto test_ratchet test_adaptive test_multipath test_tls test_ids \
        clean distclean
