API ?= 35

# Auto-detect NDK
ifeq ($(OS),Windows_NT)
  NDK_ROOT ?= $(subst \,/,$(firstword $(wildcard     $(subst \,/,$(LOCALAPPDATA))/Android/Sdk/ndk/*     $(subst \,/,$(ANDROID_HOME))/ndk/*     D:/AndroidSDK/ndk/*)))
  PREBUILT := windows-x86_64
  CLANG_BASE := aarch64-linux-android$(API)-clang
  NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/$(CLANG_BASE).cmd
else
  NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT))
  PREBUILT := linux-x86_64
  NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/aarch64-linux-android$(API)-clang
endif

SRCS := \
  src/core/main.c \
  src/core/offsets_json.c \
  src/core/util.c \
  src/core/fops.c \
  src/core/perf_sp_leak.c \
  src/core/exp64_launcher.c \
  src/exp64_blob.S

EMBED_DIR := build/embed
EMBED_EXP64 := $(EMBED_DIR)/cve_exp64_arm64

API64 ?= 28
NDK_CC64 := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/aarch64-linux-android$(API64)-clang
# ONDK (topjohnwu) puts the oldest supported API (28) in lib direction only; aarch64
# clang accepts any API for the sysroot-agnostic -static build.  Fall back to plain
# aarch64-linux-android-clang if the APIfied name is missing.
NDK_CC64 ?= $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/aarch64-linux-android-clang

# Device offsets are selected at runtime from uname -r.
TARGET_CONFIG ?= target.h

CFLAGS = -O2 -flto -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  -Isrc/core -Isrc/kernels -DTARGET_CONFIG_H=\"$(TARGET_CONFIG)\"
LDFLAGS := -fPIE -pie -pthread -flto

.PHONY: all clean product

all: ghostlock

ghostlock: $(SRCS) $(EMBED_EXP64)
	@echo "Using NDK compiler: $(NDK_CC)"
	@echo "Target config: $(TARGET_CONFIG)"
	$(NDK_CC) $(CFLAGS) $(LDFLAGS) $(filter %.c %.S,$^) -o ghostlock

$(EMBED_EXP64): src/exp64/main.c src/exp64/stack.c | $(EMBED_DIR)
	@echo "Building embedded exp64 stage: $(NDK_CC64)"
	$(NDK_CC64) -O2 -g0 -Wall -Isrc/core -fPIE -pthread \
	  -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
	  src/exp64/main.c src/exp64/stack.c -static -pie -o $@

$(EMBED_DIR):
	mkdir -p $(EMBED_DIR)

product: ghostlock
	@echo "=== ghostlock binary ready: ./ghostlock ==="
	@echo "构建 APK: .\gradlew.bat :app:assembleDebug"

clean:
	rm -f ghostlock
	rm -rf build
