# Makefile — ELF Loader PS5 (FW 11.xx)
#
# Requiere ps5-payload-sdk instalado.
# Exportar: export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk

PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk

# ── Toolchain ──────────────────────────────────────────────────────────────

CC      = $(PS5_PAYLOAD_SDK)/bin/x86_64-ps5-payload-cc
STRIP   = $(PS5_PAYLOAD_SDK)/bin/x86_64-ps5-payload-strip
OBJCOPY = llvm-objcopy

# ── Flags ──────────────────────────────────────────────────────────────────

CFLAGS  = -Wall -Wextra -O2 -std=c11                   \
          -fno-stack-protector                          \
          -fno-builtin                                  \
          -I$(PS5_PAYLOAD_SDK)/include                  \
          -I.

LDFLAGS = -L$(PS5_PAYLOAD_SDK)/lib                     \
          -nostdlib                                     \
          -Wl,--entry=_start                            \
          -Wl,-z,max-page-size=0x4000

LIBS    = -lkernel_sys

# ── Fuentes ────────────────────────────────────────────────────────────────

SRCS = main.c elfldr.c pt.c
OBJS = $(SRCS:.c=.o)

# ── Targets ────────────────────────────────────────────────────────────────

TARGET = elfldr.elf

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Compilado: $@"

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

# ── Despliegue rápido (requiere PS5_HOST exportado) ────────────────────────
# Uso: make deploy PS5_HOST=192.168.1.50

deploy: $(TARGET)
	@if [ -z "$(PS5_HOST)" ]; then \
	    echo "ERROR: PS5_HOST no definido. Usa: make deploy PS5_HOST=IP"; \
	    exit 1; \
	fi
	cat $(TARGET) | nc -q0 $(PS5_HOST) 9020
	@echo "Enviado a $(PS5_HOST):9020"
