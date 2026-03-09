# CLAUDE.md

本文件为 AI 协作者提供项目上下文。写代码时请使用中文注释。

## 项目定位

XiaM 是基于 frida-rust 仓库构建的 **自研 Android ARM64 动态插桩框架**，目标是在 root 设备上实现 Frida 级别的 hook 能力，同时尽可能规避常见反检测手段。上游 frida/frida-gum/frida-sys 等 crate 属于原始 frida-rust 项目，**XiaM 不依赖它们**。

## Workspace 结构

```
frida-rust/
├─ examples/
│  ├─ agent/                # Android SO (cdylib libXiaM.so)
│  │  ├─ src/lib.rs         # TCP 重连 + 命令分发 + spawn 屏障
│  │  └─ src/js.rs          # jsinit / loadjs / reloadjs 处理
│  ├─ agent-host/           # Windows CLI — REPL + spawn 自动化
│  ├─ agent-protocol/       # 共享协议 (4 字节 LE 帧 + JSON)
│  ├─ injector/             # 新注入器 (ptrace + memfd，隐蔽注入)
│  │  ├─ src/main.rs        # 入口：embed loader.bin + libXiaM.so
│  │  ├─ src/ptrace.rs      # ptrace attach/detach, ARM64 寄存器操作, 远程函数调用
│  │  ├─ src/remote.rs      # PTRACE_POKETEXT 写内存, /proc/maps 解析
│  │  ├─ src/memfd.rs       # memfd_create + 抽象 Unix socket SCM_RIGHTS
│  │  ├─ src/inject.rs      # LibcOffsets/DlOffsets/StringTable + 注入编排
│  │  └─ loader/            # C shellcode (连接 socket, 接收 memfd, dlopen)
│  ├─ zymbiote/             # 旧注入器 (Zymbiote, ptrace-free /proc/pid/mem 方式)
│  └─ scripts/              # 测试用 JS 脚本 (test_spawn.js 等)
├─ quickjs-hook/            # 独立 crate (workspace exclude)
│  ├─ src/
│  │  ├─ hook_engine.c      # ARM64 inline hook 引擎 (C)
│  │  ├─ arm64_writer.c     # ARM64 指令生成器
│  │  ├─ arm64_relocator.c  # ARM64 指令重定位器
│  │  ├─ lib.rs             # Rust 包装: JSEngine, init_hook_engine
│  │  └─ jsapi/             # Frida 风格 JS API (见下方 API 参考)
│  └─ quickjs-src/          # QuickJS C 源码
├─ ldmonitor*/              # eBPF 库加载监控 (aya, 未完成, 需 bpf-linker)
├─ justfile                 # 交叉编译 + 部署命令
└─ .cargo/config.toml       # NDK linker 配置
```

## 构建命令

```bash
just agent            # 编译 libXiaM.so (Android release)
just host             # 编译 agent-host.exe (Windows)
just injector         # 编译 xiam-inject (Android, ptrace+memfd 注入器)
just zymbiote         # 编译 xiam-zymbiote (Android, 旧 Zymbiote 注入器)
just push             # 推送 libXiaM.so 到设备
just push-injector    # 推送 xiam-inject 到设备
just push-zymbiote    # 推送 xiam-zymbiote 到设备
just all              # 编译全部 + 推送
just forward          # adb reverse tcp:12708 tcp:12708
just run              # 运行 agent-host REPL
just spawn script.js  # spawn 模式：auto loadjs + resume
```

### 交叉编译环境
- Android NDK 27 (`%LOCALAPPDATA%\Android\Sdk\ndk\27.0.12077973`)
- LLVM for Windows (`C:\Program Files\LLVM\bin\libclang.dll`, bindgen 需要)
- `rustup target add aarch64-linux-android`
- justfile 已配置 CC/AR/LINKER/BINDGEN 环境变量

## 两套注入方案

### 1. ptrace + memfd 注入器 (新, `examples/injector/`)

仿照 rustFrida 实现的隐蔽注入方案，核心流程：

```
xiam-inject (root, Android)
    │
    ├─ 1. memfd_create("xiam") ← 写入 libXiaM.so 到匿名内存文件
    ├─ 2. 创建抽象 Unix socket @xiam_socket 并监听
    ├─ 3. ptrace attach 目标进程
    │     ├─ 解析自身和目标的 libc/libdl 基址 → 计算函数偏移
    │     ├─ 远程 mmap RWX → 写入 loader shellcode
    │     ├─ 远程 malloc → 写入 LibcOffsets / DlOffsets / StringTable
    │     └─ 远程调用 shellcode(offsets, dl, strings)
    │
    ├─ 4. shellcode (目标进程内执行):
    │     ├─ connect(@xiam_socket) → 发送 "HELLO_LOADER"
    │     ├─ recvmsg SCM_RIGHTS → 获得 memfd fd
    │     ├─ dlopen("/proc/self/fd/<memfd>")  ← 关键: 无磁盘文件
    │     ├─ dlsym("hello_entry") → pthread_create
    │     └─ 返回 → injector munmap shellcode + detach
    │
    └─ 5. agent init_array / hello_entry 触发:
          ├─ spawn 屏障阻塞 (等 host resume)
          └─ 后台线程 TCP 连接 host:12708
```

**隐蔽效果**: maps 中显示 `/memfd:xiam (deleted)` 而非 SO 磁盘路径。

**关键结构体** (inject.rs 与 loader.c 必须完全对齐):
- `LibcOffsets` — 15 个 libc 函数地址 (malloc, free, socket, connect, write, close, mprotect, mmap, munmap, recvmsg, pthread_create, pthread_detach, snprintf, memcpy, strlen)
- `DlOffsets` — 3 个 libdl 函数地址 (dlopen, dlsym, dlerror)
- `StringTable` — 8 组 (ptr: u64, len: u32) (socket_name, hello_msg, sym_name, pthread_err, dlsym_err, proc_path, cmdline, output_path)

### 2. Zymbiote 注入器 (旧, `examples/zymbiote/`)

ptrace-free 方案，通过 `/proc/<zygote_pid>/mem` 直接写入 Zygote 进程空间：
- 解析 ELF → 找 linker_get_page_size 等 slot → 写入 shellcode
- 不需要 ptrace，但 SO 文件必须在磁盘上 → 不隐蔽
- 交互式 REPL: start/stop/status

## 通信协议

```
agent-host (Windows)  ←── TCP :12708 ──→  libXiaM.so (Android)
```

- 帧格式: 4 字节 LE 长度 + JSON payload
- 握手: agent 连接后发送 `Hello { pid, version, transport, capabilities, spawn }`
- 请求/响应: `Request { id, command, args }` / `Response { id, status, data, error_code, error_message }`
- 异步事件: `Event { event, data }` (hook 回调中通过 `send()` 触发)

### Spawn 模式

agent-host `--spawn script.js` → agent 连接后自动执行:
1. `loadjs script.js` — 在 app 代码执行前注入 hook
2. `resume` — 释放 spawn 屏障，app 主线程继续

spawn 屏障: `init_array` / `hello_entry` 入口默认用 `Condvar` 阻塞 (5s 超时防冻结)。

## JS API 参考

```javascript
// 命令 (REPL 中执行)
jsinit                           // 初始化 QuickJS 引擎 (自动, 通常不需手动)
loadjs test.js                   // 加载 JS 脚本文件
loadjs send("hi")                // 内联 JS 表达式
reloadjs test.js                 // 热加载: 清理所有 hook → 重建引擎 → 执行

// Process
Process.id                       // pid
Process.arch                     // "arm64"
Process.enumerateModules()       // [{name, base, size, path}]

// Module
Module.findExportByName("libc.so", "open")   // NativePointer
Module.getBaseAddress("libc.so")             // NativePointer

// Interceptor (ARM64 inline hook)
Interceptor.attach(addr, {
    onEnter: function(args) { /* args[0]~args[7] = x0~x7 */ },
    onLeave: function(retval) { /* retval = x0 */ }
});
Interceptor.detachAll();

// 低级 hook API
hook(addr, callback)             // attach-style hook
unhook(addr)                     // 移除 hook

// Memory
Memory.readU8/readU16/readU32/readU64(ptr)
Memory.readPointer(ptr)
Memory.readCString(ptr) / Memory.readUtf8String(ptr)
Memory.readByteArray(ptr, len)
Memory.writeU8/writeU16/writeU32/writeU64(ptr, val)

// 消息
send(message)                    // 缓冲消息, loadjs 返回时推送给 host
console.log/warn/error           // 输出到 logcat + 推送到 host
ptr("0x12345678")                // 构造 NativePointer
```

## Hook 引擎原理

hook_engine.c 实现 ARM64 inline hook:

1. **mmap 1MB R-X 内存池** — `get_or_init_engine()` 时分配 (先 RW, init 后 mprotect 为 R-X)
2. **代码生成通过 /proc/self/mem** — arm64_writer 输出到栈临时缓冲区，再通过 `proc_mem_write()` 写入 R-X 池，无需 RWX
3. **hook_attach** — 搜集目标函数头部指令，relocate 到 trampoline (pool 内)
4. **生成 thunk** — 保存寄存器 → on_enter 回调 → trampoline(原函数) → on_leave → 恢复
5. **patch 目标入口** — MOVZ/MOVK + BR X16 跳到 thunk (通过 /proc/self/mem 写入)
6. **HookEntry 分配在堆上** (malloc)，不占用 pool

## 反检测措施 (已实现)

| 措施 | 效果 |
|------|------|
| RWX 消除 | 内存池 mmap RW → init 后 mprotect R-X, 写入通过 /proc/self/mem |
| HookEntry 堆分配 | entry 用 malloc 不在 pool 中, 减少 R-X 匿名段大小特征 |
| 线程名伪装 | agent 线程名 "pool-2-thread-1" (模仿 Java 线程池) |
| memfd 注入 | maps 显示 `/memfd:xiam (deleted)` 而非磁盘 SO 路径 |
| NativePointer AtomicU32 | NATIVE_POINTER_CLASS_ID 从 thread_local Cell 改为 static AtomicU32 |

### 尚存的可检测指纹
- TCP localhost:12708 通信
- 1MB 匿名 r-xp 段 (hook pool)
- logcat 标签 "XiaM"
- `/memfd:xiam (deleted)` maps 条目名称

## 已知缺陷

### P0 — 功能
1. **新注入器未实际测试** — ptrace+memfd injector 代码完成但未在设备上验证
2. **agent 命令大量 stub** — list_modules/list_threads/find_symbol/read_memory/trace 均 NotImplemented

### P1 — 安全/隐蔽
3. **memfd 名称可改进** — "xiam" 仍有特征，可改为空名或伪装
4. **TCP 端口固定** — 12708 未随机化
5. **logcat tag "XiaM"** — 应替换为无特征名

### P2 — 工程
6. **无 Interceptor.detach(单个)** — 只有 detachAll
7. **quickjs-hook 无测试** — JS API 层无单元测试
8. **ldmonitor 未完成** — 需要 bpf-linker, 编译未通过
9. **loader.o 残留** — `examples/injector/loader/loader.o` 应加入 .gitignore

## 开发路线图

### 已完成 ✅
- Phase 1: 结构化协议 + Hello 握手 + TCP 自动重连
- Phase 3 (部分): QuickJS + Frida 风格 JS API + ARM64 inline hook + 热加载
- 反检测: RWX 消除 + 线程伪装 + NativePointer 修复
- 注入: Zymbiote (旧) + ptrace+memfd (新)

### 下一步
1. **设备验证 ptrace+memfd 注入器** — 推送 xiam-inject + libXiaM.so, 对目标进程执行完整注入流程
2. **修复注入器实际问题** — 根据设备测试结果修复 (预期: 偏移计算/shellcode 执行/socket 连接)
3. **减少可检测指纹** — memfd 名称伪装、TCP 端口随机化、logcat tag 替换
4. **实现剩余 agent 命令** — list_modules 复用 Process.enumerateModules, find_symbol 复用 Module.findExportByName
5. **Interceptor.detach(handle)** — 单个 hook 卸载

### 远期
- Phase 2: host 拆分 (core / CLI / MCP)
- Phase 4: KPM 内核模块集成
- ldmonitor: eBPF 库加载监控

## 编码约定

- 注释用中文
- quickjs-hook 是独立 crate (Cargo.toml exclude)，agent 通过 `cfg(target_os = "android")` 条件依赖
- 非 Android 平台的 JS 命令返回 NotImplemented (stub)
- hook_engine.c / arm64_writer.c / arm64_relocator.c 是纯 C，通过 build.rs (cc + bindgen) 编译
- injector 的 `#[repr(C)]` 结构体必须与 loader.c 完全对齐 (字段顺序 + 大小)
- bindgen 交叉编译需要 `-isystem` 显式指定 NDK sysroot include 路径
