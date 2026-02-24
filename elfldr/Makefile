# elfldr/Makefile
#
# Build the ELF loader payload using ps5-payload-sdk.
#
# Requirements:
#   export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
#
# Usage:
#   make          — build elfldr.elf
#   make clean    — remove build artifacts
#   make install  — copy elfldr.elf to ../payloads/

PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk

# Toolchain from ps5-payload-sdk
CC      := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
LD      := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
OBJCOPY := $(PS5_PAYLOAD_SDK)/bin/prospero-objcopy

# Source files
SRCS := main.c elfldr.c pt.c
OBJS := $(SRCS:.c=.o)
TARGET := elfldr.elf

# Compiler flags
CFLAGS := \
    -target x86_64-sie-ps5 \
    -fPIE \
    -ffreestanding \
    -fno-builtin \
    -O2 \
    -Wall \
    -Wextra \
    -I$(PS5_PAYLOAD_SDK)/include \
    -I.

# Linker flags — produce a bare ELF, no standard startup files
LDFLAGS := \
    -target x86_64-sie-ps5 \
    -fPIE \
    -nostdlib \
    -Wl,-e,elfldr_main \
    -Wl,--build-id=none \
    -L$(PS5_PAYLOAD_SDK)/lib \
    -lkernel_stub

# ─── Targets ──────────────────────────────────────────────────────────────────

.PHONY: all clean install check-sdk

all: check-sdk $(TARGET)

check-sdk:
	@if [ ! -d "$(PS5_PAYLOAD_SDK)" ]; then \
	    echo ""; \
	    echo "  ERROR: PS5_PAYLOAD_SDK not found at: $(PS5_PAYLOAD_SDK)"; \
	    echo ""; \
	    echo "  Install ps5-payload-sdk and set:"; \
	    echo "    export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk"; \
	    echo ""; \
	    exit 1; \
	fi

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^
	@echo ""
	@echo "  Built: $@"
	@ls -lh $@
	@echo ""

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	cp $(TARGET) ../payloads/
	@echo "  Installed: ../payloads/$(TARGET)"
