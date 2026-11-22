# Makefile for Linux EDR Evasion Toolkit (io_uring & LD_PRELOAD)
CC ?= gcc
CFLAGS ?= -Wall -O2

all: evasion_hooks.so evasion_ops

evasion_hooks.so: evasion_toolkit.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< -ldl

evasion_ops: evasion_toolkit.c
	$(CC) $(CFLAGS) -o $@ $< -luring

clean:
	rm -f evasion_hooks.so evasion_ops
