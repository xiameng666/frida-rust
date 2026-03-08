# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. 写代码时请使用中文注释

## Project Overview

本项目基于 frida-rust 仓库，扩展了一套自定义的 Android ARM64 动态插桩框架。核心组件：
- **agent** — 注入到 Android 进程的 cdylib SO
- **agent-host** — Windows 端 REPL 控制工具
- **agent-protocol** — 共享的结构化通信协议
- **quickjs-hook** — QuickJS + ARM64 inline hook 引擎 + Frida 风格 JS API

上游 frida/frida-gum/frida-sys 等 crate 屚于原始 frida-rust 项目，本项目不依赖它们。

## Workspace 结构

```
frida-rust/
├─ examples/
│  ├─ agent/              # Android SO (cdylib), JNI_OnLoad/init_array 入口
│  │  ├─ src/lib.rs       # TCP 重连 + 命令分发
│  │  └─ src/js.rs        # jsinit/loadjs/reloadjs 处理
│  ├─ agent-host/         # Windows CLI REPL
│  └─ agent-protocol/     # 共享协议 (frame + message)
├─ quickjs-hook/           # 独立 crate (不在 workspace members 内, exclude)
│  ├─ src/
│  │  ├─ hook_engine.c    # ARM64 inline hook 引擎 (C)
│  │  ├─ arm64_writer.c   # ARM64 指令生成器
│  │  ├─ arm64_relocator.c# ARM64 指令重定位
│  │  ├─ lib.rs           # Rust 包装: JSEngine, init_hook_engine
│  │  ├─ ffi.rs           # bindgen 生成的 FFI 绑定
│  │  ├─ runtime.rs       # QuickJS Runtime 包装
│  │  ├─ context.rs       # QuickJS Context 包装
│  │  ├─ value.rs         # QuickJS JSValue 包装
│  │  └─ jsapi/           # Frida 风格 JS API
│  │     ├─ mod.rs        # register_all_apis()
│  │     ├─ interceptor.rs# Interceptor.attach/detachAll
│  │     ├─ module_api.rs # Module.findExportByName/getBaseAddress
│  │     ├─ process.rs    # Process.enumerateModules/id/arch
│  │     ├─ memory.rs     # Memory.readU8/writeU8/readCString/...
│  │     ├─ hook_api.rs   # hook()/unhook() 低级 API
│  │     ├─ ptr.rs        # NativePointer / ptr() 构造
│  │     ├─ send.rs       # send() 消息缓冲
│  │     └─ console.rs    # console.log/warn/error
│  └─ quickjs-src/         # QuickJS C 源码
├─ justfile                 # Android 交叉编译命令
└─ .cargo/config.toml       # NDK linker 配置
```

## Build Commands

```bash
# Android agent SO (release)
just agent

# Windows agent-host (release)
just host

# 推送 SO 到设备
just push

# adb 端口转发
just forward

# 运行 agent-host REPL
just run

# Windows 本地测试
cargo test -p agent-protocol
cargo test -p agent
```

### 交叉编译依赖
- Android NDK 27 (path: `%LOCALAPPDATA%\Android\Sdk\ndk\27.0.12077973`)
- LLVM for Windows (`C:\Program Files\LLVM\bin\libclang.dll`, bindgen 需要)
- Rust target: `rustup target add aarch64-linux-android`
- justfile 已配置所有 CC/AR/LINKER/BINDGEN 环境变量

## 通信协议

```
agent-host (Windows)  ←─ TCP :12708 ─→  libagent.so (Android)
         │                                    │
    REPL/CLI                            JNI_OnLoad 启动
    发送 Request                       自动重连 TCP
    显示 Response                     分发命令并响应
```

- 帧格式: 4字节 LE 长度 + JSON payload
- 握手: agent 连接后发送 Hello (pid, version, capabilities)
- 消息: Request {id, command, args} / Response {id, status, data, error_code, error_message}

## JS API 参考

```javascript
// 初始化 (REPL 中执行)
jsinit
loadjs test.js      // 读取文件并执行
loadjs send("hi")   // 内联 JS
reloadjs test.js    // 热加载: 清理所有 hook → 重建引擎 → 执行

// Process
Process.id           // pid
Process.arch         // "arm64"
Process.enumerateModules()  // [{name, base, size, path}]

// Module
Module.findExportByName("libc.so", "open")  // NativePointer
Module.getBaseAddress("libc.so")            // NativePointer

// Interceptor (ARM64 inline hook)
Interceptor.attach(addr, {
    onEnter: function(args) { /* args[0]~args[7] = x0~x7 */ },
    onLeave: function(retval) { /* retval = x0 */ }
});
Interceptor.detachAll();

// 低级 hook API
hook(addr, callback, stealth?)   // stealth=true 用 wxshadow
unhook(addr)

// Memory
Memory.readU8/readU16/readU32/readU64(ptr)
Memory.readPointer(ptr)
Memory.readCString(ptr) / Memory.readUtf8String(ptr)
Memory.readByteArray(ptr, len)
Memory.writeU8/writeU16/writeU32/writeU64(ptr, val)

// 消息
send(message)        // 缓冲到 Vec, loadjs 完成后返回
console.log/warn/error
ptr("0x12345678")   // 构造 NativePointer
```

## Hook 引擎工作原理

hook_engine.c 实现 ARM64 inline hook:

1. **mmap 1MB RWX 内存池** — jsinit 时自动分配
2. **hook_attach** — 搜集目标函数头部 20字节(5条指令)，relocate 到 trampoline
3. **生成 thunk** — 保存寄存器 → on_enter → trampoline(原函数) → on_leave → 恢复寄存器
4. **patch 目标入口** — MOVZ/MOVK + BR 跳到 thunk
5. 两种模式: normal (mprotect RWX) / stealth (prctl wxshadow, 小米内核特有)

## 已知缺陷

### P0 - 功能缺陷
1. **Interceptor.attach 未验证** — hook_engine_init 刚加上，Interceptor.attach 在设备上还未成功运行过，可能存在 mprotect 失败等问题
2. **hook_attach 错误信息丢失** — interceptor.rs 只抛 "Interceptor.attach failed"，不报告具体错误码 (HOOK_ERROR_MPROTECT_FAILED 等)
3. **目标页 mprotect 后未恢复** — hook_attach normal 模式 patch 完目标后，页保持 RWX，应恢复为 R-X
4. **Process.enumerateModules() 返回非 SO 条目** — 解析 /proc/self/maps 会包含 .oat/.vdex/.art 等，与 Frida 行为不一致

### P1 - 安全/隐蔽缺陷
5. **1MB RWX 内存池可检测** — /proc/self/maps 里有 rwxp 匿名段，易被安全检测发现
6. **stealth 模式未暴露给 JS** — Interceptor.attach 写死 stealth=0，应支持可选 options
7. **Memory.write* 无权限检查** — 直接解引用写入，无效地址会崩溃

### P2 - 工程缺陷
8. **agent 命令大量 stub** — list_modules/list_threads/find_symbol/read_memory/trace_start/trace_stop 均返回 NotImplemented
9. **无 Interceptor.detach(单个)** — 只有 detachAll，缺少按 handle 卸载单个 hook
10. **quickjs-hook 无测试** — JS API 层没有任何单元测试
11. **agent/.cargo/config.toml linker 配置冲突** — 使用裸命令名，与根目录 .cargo/config.toml 和 justfile 重复配置
12. **2个编译警告未修复** — ptr.rs unused doc comment, process.rs unused variable

## 开发路线图

### Phase 1 - 控制面稳定化 ✅ 完成
- 结构化 Request/Response 协议
- Hello 握手 + 能力声明
- TCP 自动重连 + logcat 日志

### Phase 3 (部分) - 用户空间能力 ✅ 部分完成
- QuickJS 集成 + Frida 风格 JS API
- ARM64 inline hook 引擎 (hook_engine.c)
- 热加载 (reloadjs)
- 已实现: Interceptor, Module, Process, Memory, send, NativePointer, console, hook/unhook

### 下一步实现顺序
1. **验证 Interceptor.attach 可用** — 在设备上测试 hook open() 并确认回调触发
2. **修复 P0 缺陷** — 错误码透传、mprotect 恢复、maps 过滤
3. **实现剩余 agent 命令** — list_modules 可复用 Process.enumerateModules，find_symbol 复用 Module.findExportByName，read_memory 复用 Memory API
4. **暴露 stealth 选项** — Interceptor.attach(addr, callbacks, {stealth: true})
5. **Phase 2** — 拆分 host 为 core/CLI/MCP
6. **Phase 4** — KPM 集成

## 编码约定

- 注释用中文
- quickjs-hook 是独立 crate (Cargo.toml exclude)，agent 通过 `cfg(target_os = "android")` 条件依赖它
- 非 Android 平台的 JS 命令返回 NotImplemented (stub)
- hook_engine.c / arm64_writer.c / arm64_relocator.c 是纯 C 代码，通过 build.rs (cc + bindgen) 编译
- bindgen 交叉编译时需要 -isystem 显式指定 NDK sysroot include 路径 (Windows libclang 不支持 --sysroot)
