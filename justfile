# XiaM justfile

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

# adb 端口转发
forward:
    adb reverse tcp:12708 tcp:12708
