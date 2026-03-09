# Build Zymbiote notification stub
#
# Requires: Android NDK (set NDK_HOME or ANDROID_NDK_HOME)
#
# Usage:
#   make              — build stub.bin
#   make clean        — remove build artifacts

NDK_HOME ?= $(ANDROID_NDK_HOME)
TOOLCHAIN := $(NDK_HOME)/toolchains/llvm/prebuilt/$(shell uname -s | tr A-Z a-z)-x86_64
CC := $(TOOLCHAIN)/bin/clang
OBJCOPY := $(TOOLCHAIN)/bin/llvm-objcopy
TARGET := --target=aarch64-linux-android31

.PHONY: all clean

all: stub.bin

stub.o: stub.S
	$(CC) $(TARGET) -nostdlib -nostartfiles -nodefaultlibs -fPIC -O2 -c $< -o $@

stub.bin: stub.o
	$(OBJCOPY) -O binary -j .text $< $@
	@echo "[+] stub.bin: $$(wc -c < $@) bytes"

clean:
	rm -f stub.o stub.bin
