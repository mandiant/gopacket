# Makefile for gopacket

CC=gcc
TOOLS=$(shell ls tools/)

all: build

build:
	@mkdir -p bin/
	@for tool in $(TOOLS); do \
		echo "[*] Building $$tool..."; \
		CGO_ENABLED=1 go build -o bin/$$tool -ldflags '-linkmode external -extldflags "-static-libgcc"' tools/$$tool/main.go; \
	done

clean:
	rm -rf bin/

.PHONY: all build clean
