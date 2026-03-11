# XiaM justfile
export NO_COLOR := "1"
set windows-shell := ["cmd.exe", "/c"]

# Android NDK 配置
android_target := "aarch64-linux-android"
android_api    := "31"
ndk_root       := "C:\\Users\\24151\\AppData\\Local\\Android\\Sdk\\ndk\\27.0.12077973"
ndk_toolchain  := ndk_root + "\\toolchains\\llvm\\prebuilt\\windows-x86_64"
ndk_bin        := ndk_toolchain + "\\bin"
ndk_sysroot    := ndk_toolchain + "\\sysroot"

export CC_aarch64_linux_android           := ndk_bin + "\\aarch64-linux-android" + android_api + "-clang.cmd"
export AR_aarch64_linux_android           := ndk_bin + "\\llvm-ar.exe"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER := ndk_bin + "\\aarch64-linux-android" + android_api + "-clang.cmd"
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android := "--sysroot=" + ndk_sysroot + " -target aarch64-linux-android" + android_api
export LIBCLANG_PATH := "C:\\Program Files\\LLVM\\bin"

# 编译 XiaM SO (release, Android)
agent:
    cargo build -p agent --target {{android_target}} --release

# 编译 XiaM-host.exe (Windows)
host:
    cargo build -p agent-host --release

# 运行 XiaM-host
run:
    cargo run -p agent-host --release

# 推送 SO 到设备（经 /sdcard 中转，解决 fchown 权限问题）
push: agent
    adb push target/{{android_target}}/release/libXiaM.so //sdcard/libXiaM.so
    adb shell su -c "cp /sdcard/libXiaM.so /data/local/tmp/libXiaM.so"
    adb shell su -c "chmod 755 /data/local/tmp/libXiaM.so"
    adb shell su -c "ls -la /data/local/tmp/libXiaM.so"
    adb shell rm //sdcard/libXiaM.so

# 部署（push 已包含设权限）
deploy: push
    @echo "deployed to /data/local/tmp/libXiaM.so"

# 编译 injector (Android)
injector:
    cargo build -p injector --target {{android_target}} --release

# 推送 injector 到设备
push-injector: injector
    -adb shell su -c "pkill xiam-inject" 2>nul
    adb push target/{{android_target}}/release/xiam-inject //sdcard/xiam-inject
    adb shell su -c "cp /sdcard/xiam-inject /data/local/tmp/xiam-inject"
    adb shell su -c "chmod 755 /data/local/tmp/xiam-inject"
    adb shell rm //sdcard/xiam-inject

# 推送并启动交互式注入器
inject:
    just push-injector
    just deploy
    adb shell su -c /data/local/tmp/xiam-inject

# spawn 模式：auto loadjs + resume（指定 PC 上的 JS 脚本）
# 用法: just spawn hook.js
spawn script:
    cargo run -p agent-host --release -- --spawn {{script}}

# 编译全部 + 推送 agent/injector 到设备
all: agent host injector
    just push
    just push-injector
    @echo "all done"

# 编译 zymbiote stub (ARM64 shellcode → stub.bin)
zymbiote-stub:
    {{ndk_bin}}\\clang.exe --target=aarch64-linux-android{{android_api}} -nostdlib -nostartfiles -nodefaultlibs -fPIC -O2 -c examples/zymbiote/stub/stub.S -o examples/zymbiote/stub/stub.o
    {{ndk_bin}}\\llvm-objcopy.exe -O binary -j .text examples/zymbiote/stub/stub.o examples/zymbiote/stub/stub.bin

# 编译 zymbiote (Route A, 需先 build agent + stub)
zymbiote: agent zymbiote-stub
    cargo build -p zymbiote --target {{android_target}} --release

# 推送 zymbiote 到设备
push-zymbiote: zymbiote
    -adb shell su -c "pkill xiam-zymbiote" 2>nul
    adb push target/{{android_target}}/release/xiam-zymbiote //sdcard/xiam-zymbiote
    adb shell su -c "cp /sdcard/xiam-zymbiote /data/local/tmp/xiam-zymbiote"
    adb shell su -c "chmod 755 /data/local/tmp/xiam-zymbiote"
    adb shell rm //sdcard/xiam-zymbiote

# 一键编译 + 推送 + 启动 zymbiote
zymbiote-deploy: forward push-zymbiote
    adb shell su -c /data/local/tmp/xiam-zymbiote

# 编译 ldmonitor
ldmonitor:
    cargo build -p ldmonitor --target {{android_target}} --release

# 推送 ldmonitor 到设备
push-ldmonitor: ldmonitor
    adb push target/{{android_target}}/release/ldmonitor //sdcard/ldmonitor
    adb shell su -c "cp /sdcard/ldmonitor /data/local/tmp/ldmonitor"
    adb shell su -c "chmod 755 /data/local/tmp/ldmonitor"
    adb shell rm //sdcard/ldmonitor

# 编译并运行 raw syscall 测试
test-syscall:
    {{ndk_bin}}\\aarch64-linux-android{{android_api}}-clang.cmd -O2 -o tests/test_raw_syscall tests/test_raw_syscall.c -static
    adb push tests/test_raw_syscall //sdcard/test_raw_syscall
    adb shell su -c "cp /sdcard/test_raw_syscall /data/local/tmp/test_raw_syscall"
    adb shell su -c "chmod 755 /data/local/tmp/test_raw_syscall"
    adb shell rm //sdcard/test_raw_syscall
    adb shell su -c /data/local/tmp/test_raw_syscall

# 编译并推送 pwrite 测试
test-pwrite:
    {{ndk_bin}}\\aarch64-linux-android{{android_api}}-clang.cmd -O2 -o tests/test_pwrite tests/test_pwrite.c -static
    adb push tests/test_pwrite //sdcard/test_pwrite
    adb shell su -c "cp /sdcard/test_pwrite /data/local/tmp/test_pwrite"
    adb shell su -c "chmod 755 /data/local/tmp/test_pwrite"
    adb shell rm //sdcard/test_pwrite
    @echo "=== Test 1: self pwrite (as root) ==="
    adb shell su -c /data/local/tmp/test_pwrite self
    @echo ""
    @echo "=== Test 2: cross-process pwrite (fork) ==="
    adb shell su -c /data/local/tmp/test_pwrite fork

# adb 端口转发
forward:
    adb shell su -c "setenforce 0"
    adb reverse tcp:12708 tcp:12708
