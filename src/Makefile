# Makefile for Linux EDR Evasion & Telemetry Assessment Lab
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -Iinclude
LDFLAGS ?= -ldl
URING_LDFLAGS ?= -luring

TARGET_SO = libevasion_hooks.so
TARGET_CLI = evasion_lab
LEGACY_OPS = evasion_ops

all: $(TARGET_SO) $(TARGET_CLI)

$(TARGET_SO): hooks/ld_hooks.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< $(LDFLAGS)

$(TARGET_CLI): cli/main.c engine/uring_ops.c
	$(CC) $(CFLAGS) -o $@ $^ $(URING_LDFLAGS)

legacy: legacy/evasion_toolkit_monolithic.c
	$(CC) -Wall -O2 -shared -fPIC -o evasion_hooks.so $< -ldl
	$(CC) -Wall -O2 -o $(LEGACY_OPS) $< -luring

clean:
	rm -f $(TARGET_SO) $(TARGET_CLI) $(LEGACY_OPS) evasion_hooks.so
	rm -rf /tmp/evasion_lab

help:
	@echo "Available build targets:"
	@echo "  make              - Build both libevasion_hooks.so and evasion_lab"
	@echo "  make legacy       - Build legacy monolithic thesis binaries"
	@echo "  make clean        - Remove compiled binaries and temporary artifacts"

.PHONY: all clean legacy help
