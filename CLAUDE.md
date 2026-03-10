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

## Hook 引擎详细原理

hook_engine.c 实现 ARM64 inline hook，以下是完整生命周期。

### 1. 内存池初始化 (`get_or_init_engine`)

lib.rs 中通过 `std::sync::Once` 确保只初始化一次：

1. **优先 mmap RWX** — `PROT_READ|PROT_WRITE|PROT_EXEC`, `MAP_PRIVATE|MAP_ANONYMOUS`, 1MB
   - root 设备 SELinux 通常允许，pool 直接可读/写/执行
   - 日志: `[XiaM-hook] pool: mmap RWX 0x... (1024 KB)`
2. **RWX 失败 → 降级 RW→R-X** — 先 `PROT_READ|PROT_WRITE` mmap，init 后 `mprotect(R-X)`
   - pool 写入依赖 `/proc/self/mem` pwrite（部分内核会静默拒绝）
   - 日志: `[XiaM-hook] pool: RWX mmap failed (errno=...), falling back to RW→R-X`
3. **调用 `hook_engine_init(mem, 1MB)`** — 设置 g_engine 全局状态、初始化 mutex

> 设备实测: Redmi rubens (Android 13 MIUI V14) 上 RWX mmap 成功，但 `/proc/self/mem` 的 pread/pwrite **全部失败**（hardened kernel），所有操作走 direct memcpy / mprotect fallback。

### 2. Pool 内存布局

```
pool (1MB, rwxp or r-xp):
┌──────────────────┬──────────────────┬──────────────────┬───┐
│ trampoline_0     │ thunk_0          │ trampoline_1     │...│
│ (256B)           │ (512B)           │ (256B)           │   │
└──────────────────┴──────────────────┴──────────────────┴───┘
↑ exec_mem                                    exec_mem_used ↑
```

- **trampoline** (256B): 存放目标函数被覆盖的前 5 条指令（重定位后）+ 跳回原函数的 jump-back
- **thunk** (512B): 完整的 hook 调度代码（保存寄存器 → on_enter → 调用原函数 → on_leave → 恢复）
- **HookEntry** 分配在堆上 (malloc)，不占用 pool
- 分配是 bump allocator，只增不减；remove hook 后 entry 进 free_list 复用

### 3. pool_write — 统一写入接口

所有往 pool 的写入都经过 `pool_write()`:

```
pool_write(addr, src, len)
  ├─ 1. 尝试 /proc/self/mem pwrite  → 成功则返回
  └─ 2. 失败 → HOOK_LOGW + direct memcpy（RWX pool 下安全）
```

### 4. hook_attach 完整流程

JS `Interceptor.attach(target, {onEnter, onLeave})` 最终调用 C 的 `hook_attach()`:

```
hook_attach(target=0x7672e6c020, on_enter, on_leave, user_data, stealth=0)
  │
  ├─ 1. 读取目标函数前 20 字节 (5 条 ARM64 指令)
  │     ├─ /proc/self/mem pread → 成功
  │     └─ 失败 → mprotect(RWX) + memcpy（带 LOGW）
  │
  ├─ 2. 分配 trampoline (256B) + thunk (512B) from pool
  │     └─ 优先复用 free_list 中的已有分配
  │
  ├─ 3. 重定位 (arm64_relocator):
  │     ├─ 将 5 条原始指令写入 temp buffer
  │     ├─ PC-relative 指令修正（ADR/ADRP/B/CBZ/LDR literal 等）
  │     └─ pool_write → trampoline
  │
  ├─ 4. 写入 jump-back (MOVZ/MOVK/BR → target+20)
  │     └─ pool_write → trampoline[relocated_size..]
  │
  ├─ 5. 生成 thunk (arm64_writer):
  │     ├─ SUB SP, SP, #288          ; 分配 HookContext
  │     ├─ STP x0-x30 → [SP]        ; 保存所有寄存器
  │     ├─ LDR x16, =on_enter → BLR ; 调用 on_enter(ctx, user_data)
  │     ├─ LDP x0-x7 ← [SP]         ; 恢复参数（JS 可能已修改）
  │     ├─ LDR x16, =trampoline → BLR ; 调用原函数
  │     ├─ STR x0 → [SP]            ; 保存返回值
  │     ├─ LDR x16, =on_leave → BLR ; 调用 on_leave(ctx, user_data)
  │     ├─ LDR x0 ← [SP]           ; 恢复返回值（JS 可能已修改）
  │     ├─ ADD SP, SP, #288 → RET   ; 恢复栈 + 返回
  │     └─ pool_write → thunk
  │
  ├─ 6. patch 目标函数入口 (20 字节 → MOVZ/MOVK/BR X16 跳到 thunk)
  │     ├─ stealth=1 → wxshadow_patch (prctl PR_WXSHADOW_PATCH)
  │     ├─ /proc/self/mem pwrite → 成功 (LOGI)
  │     └─ 失败 → mprotect(RWX) + memcpy (LOGW + LOGI)
  │
  └─ 7. flush icache (dc cvau + ic ivau + dsb + isb)
```

### 5. 调用链 (hook 生效后)

```
其他线程调用 dlopen("libfoo.so"):
  │
  ├─ 执行到 dlopen 入口，前 5 条指令已被替换为:
  │     MOVZ X16, #thunk_lo
  │     MOVK X16, #thunk_hi, LSL #16
  │     MOVK X16, #thunk_hi32, LSL #32
  │     MOVK X16, #thunk_hi48, LSL #48
  │     BR   X16              → 跳到 thunk
  │
  ├─ thunk 执行:
  │     保存 x0-x30, SP, PC → HookContext
  │     on_enter_wrapper(ctx) → JS onEnter(args)  ← args[0]=x0 (filename)
  │     恢复 x0-x7 (JS 可能修改了参数)
  │     BLR trampoline       → 执行原始 dlopen (重定位后的 5 条指令 + jump-back)
  │     保存 x0 (返回值)
  │     on_leave_wrapper(ctx) → JS onLeave(retval)
  │     恢复 x0 (JS 可能替换了返回值)
  │     RET                   → 返回调用者
  │
  └─ 对调用者透明，如同正常调用 dlopen
```

### 6. hook 卸载 (`hook_remove` / `Interceptor.detachAll`)

```
hook_remove(target)
  ├─ stealth → wxshadow_release (恢复原始视图)
  ├─ 非 stealth → proc_mem_write 恢复原始 20 字节; 失败则 mprotect+memcpy
  ├─ flush icache
  └─ entry 移入 free_list (pool 内的 trampoline/thunk 空间保留复用)
```

`JSEngine::drop` → `cleanup_hooks()` + `cleanup_interceptor_hooks()` → 逐个 `hook_remove`。

`reloadjs` 命令: drop 旧引擎 (卸载全部 hook) → 创建新引擎 → eval 新脚本。

### 7. 日志体系

- **hook_engine.c**: `HOOK_LOGI` / `HOOK_LOGW` — Android 走 `__android_log_print` (tag: `XiaM-hook`)，非 Android 走 stderr
- **lib.rs pool 分配**: `eprintln!` (stderr)
- logcat 过滤: `adb logcat -s XiaM-hook:* XiaM:*`

## Zymbiote Route A — 注入生命周期

完整的 ptrace-free 注入流程（`examples/zymbiote/`），已在 Redmi rubens 设备验证通过。

### 阶段 1: 注入器准备 (xiam-zymbiote 进程, root)

```
xiam-zymbiote (REPL: start <pkg>)
  │
  ├─ 1. 找 Zygote64 PID (解析 /proc/*/cmdline 找 "zygote64")
  ├─ 2. 解析 pkg 的 UID (pm list packages -U)
  ├─ 3. SIGSTOP 冻结 Zygote
  ├─ 4. 打开 /proc/<zpid>/mem (O_RDWR)
  ├─ 5. 扫描 /proc/<zpid>/maps:
  │     ├─ 找 libstagefright.so 的 r-xp 映射 → shellcode 目标
  │     ├─ 解析 ELF PT_LOAD 的 p_filesz → 计算 text 段末尾 NUL padding
  │     │   padding ≥ 348B → 使用 ELF padding（不覆盖真实代码）
  │     │   padding 不足 → 降级使用 last page（可能覆盖代码）
  │     ├─ 找 libandroid_runtime.so → 解析 setArgV0Native 符号偏移
  │     └─ 收集 rw 区域（boot.art / dalvik / anon）用于 ArtMethod 搜索
  ├─ 6. 搜索 ArtMethod slot:
  │     ├─ 在 rw 区域中搜索 setArgV0Native 地址的 8 字节匹配
  │     └─ 找到的地址即为 ArtMethod.entry_point_ 字段
  ├─ 7. 创建抽象 Unix socket @xiam_zymbiote 监听
  └─ 8. 安装 hook: pwrite 到 Zygote 内存
        ├─ 备份原始数据 (shellcode 区 + ArtMethod slot)
        ├─ 填充 payload (stub.S 机器码 + StubParams 参数)
        ├─ pwrite payload → libstagefright ELF padding 区
        └─ pwrite shellcode 地址 → ArtMethod.entry_point_ slot
```

### 阶段 2: 触发 (Zygote fork → app 进程)

```
Zygote fork → com.tencent.token (PID 24502)
  │
  ├─ app 启动 → 调用 Process.setArgV0(pkg_name)
  │   → ART 查找 ArtMethod → entry_point_ 已被替换为 shellcode 地址
  │   → CPU 跳到 libstagefright ELF padding 区的 stub.S
  │
  ├─ stub.S 执行 (ARM64 shellcode, 348 bytes):
  │     ├─ 检查 UID == 目标 UID (否则跳过，恢复原函数)
  │     ├─ 恢复 ArtMethod slot 为原始值 (自我清理)
  │     ├─ socket(AF_UNIX, SOCK_STREAM) → connect(@xiam_zymbiote)
  │     ├─ write(4 字节 PID) → 通知注入器
  │     ├─ read(1 字节) → 等待注入完成信号
  │     ├─ close socket
  │     └─ 跳回原始 setArgV0Native 函数
  │
  └─ 注入器收到 PID 通知 → 进入阶段 3
```

### 阶段 3: Agent 注入 (ptrace + memfd)

```
注入器 listener 线程:
  │
  ├─ 1. ptrace attach 到 app PID
  ├─ 2. 解析双方 libc/libdl 基址 → 计算远程函数地址
  ├─ 3. remote memfd_create("jit-cache", MFD_CLOEXEC) → fd=N
  ├─ 4. 从注入器侧直接写入 /proc/<pid>/fd/N (root 权限)
  │     → 写入 libXiaM.so 全部内容 (~1.7MB)
  ├─ 5. remote dlopen("/proc/self/fd/N", RTLD_NOW)
  │     → 触发 .init_array → agent start_agent("init_array")
  ├─ 6. remote dlsym(handle, "hello_entry")
  ├─ 7. remote pthread_create(hello_entry) + pthread_detach
  ├─ 8. ptrace detach
  └─ 9. write(0x01) 到 stub socket → stub 继续执行
```

### 阶段 4: Agent 运行 (app 进程内)

```
agent init_array 触发:
  │
  ├─ 1. start_agent("init_array")  (Once 保证只执行一次)
  │     ├─ logcat: "libXiaM.so loaded via init_array"
  │     ├─ 启动通信线程 (名: "pool-2-thread-1")
  │     └─ spawn 屏障阻塞主线程 (Condvar, 5s 超时)
  │
  ├─ 2. 通信线程 TCP connect 127.0.0.1:12708 (经 adb reverse)
  │     ├─ 发送 Hello { pid, version, capabilities, spawn=true }
  │     └─ 进入请求/响应循环
  │
  ├─ 3. host 收到 spawn=true → 自动 loadjs + resume
  │     ├─ loadjs: get_or_init_engine() → 初始化 hook pool
  │     │          eval(test.js) → Interceptor.attach(dlopen, ...) → hook_attach
  │     └─ resume: signal_resume() → Condvar notify → 主线程继续
  │
  └─ 4. app 主线程恢复执行
        ├─ 后续所有 dlopen/android_dlopen_ext 调用被 hook 拦截
        ├─ on_enter JS 回调 → console.log → 推送到 host 显示
        └─ 断线自动重连 (TCP 重连循环)
```

### 清理和恢复

```
xiam-zymbiote 退出时 (exit/quit/Ctrl+C):
  ├─ Injector::restore()
  │     ├─ SIGSTOP Zygote
  │     ├─ pwrite 恢复 ArtMethod slot 原始值
  │     ├─ pwrite 恢复 shellcode 区原始数据
  │     └─ SIGCONT Zygote
  ├─ shutdown listener socket → listener 线程退出
  ├─ 删除状态文件 /data/local/tmp/.xiam-state
  └─ Injector::drop (close fds)

异常恢复 (zymbiote 崩溃后):
  ├─ 状态文件 /data/local/tmp/.xiam-state 保存了 zpid/slot/shell/orig 数据
  └─ 重新运行 xiam-zymbiote → stop → restore_from_state() → 恢复 Zygote
```

## 反检测措施 (当前状态)

- **Pool 权限**: root 设备上 pool 为 rwxp (mmap RWX)；日志明确标识降级路径
- **HookEntry 堆分配**: entry 用 malloc，不在 pool 中
- **线程名伪装**: agent 线程名 "pool-2-thread-1" (模仿 Java 线程池)
- **memfd 注入**: maps 显示 `/memfd:jit-cache (deleted)` (Route A 用 "jit-cache")
- **NativePointer AtomicU32**: NATIVE_POINTER_CLASS_ID 用 static AtomicU32
- **ELF padding shellcode**: 不覆盖真实代码，binder 线程不会 SIGILL
- **日志透明**: hook 引擎所有 fallback 路径有 LOGW 日志

### 尚存的可检测指纹
- TCP localhost:12708 通信
- 1MB 匿名 rwxp 段 (hook pool, root 设备)
- logcat 标签 "XiaM" / "XiaM-hook"
- `/memfd:jit-cache (deleted)` maps 条目

## 已知缺陷

### P0 — 功能
1. **agent 命令大量 stub** — list_modules/list_threads/find_symbol/read_memory/trace 均 NotImplemented

### P1 — 安全/隐蔽
2. **memfd 名称可改进** — "jit-cache" 仍有特征，可改为空名或伪装
3. **TCP 端口固定** — 12708 未随机化
4. **logcat tag "XiaM"** — 应替换为无特征名
5. **pool 为 rwxp** — root 设备上为了避免 proc/self/mem 问题使用 RWX，是较大的特征

### P2 — 工程
6. **无 Interceptor.detach(单个)** — 只有 detachAll
7. **quickjs-hook 无测试** — JS API 层无单元测试
8. **ldmonitor 未完成** — 需要 bpf-linker, 编译未通过

## 开发路线图

### 已完成 ✅
- Phase 1: 结构化协议 + Hello 握手 + TCP 自动重连
- Phase 3 (部分): QuickJS + Frida 风格 JS API + ARM64 inline hook + 热加载
- 反检测: RWX pool + 线程伪装 + NativePointer 修复
- 注入 Route A (Zymbiote): ELF padding 放置 + ptrace memfd 远程注入 — **设备验证通过**
- Hook engine: pool_write fallback + 全链路日志 + double-panic 修复

### 下一步
1. **减少可检测指纹** — memfd 名称伪装、TCP 端口随机化、logcat tag 替换
2. **实现剩余 agent 命令** — list_modules 复用 Process.enumerateModules, find_symbol 复用 Module.findExportByName
3. **Interceptor.detach(handle)** — 单个 hook 卸载
4. **pool 权限优化** — 探索 dual-mapping (一份 RW + 一份 R-X 共享物理页) 消除 rwxp

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
