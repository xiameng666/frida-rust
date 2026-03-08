# rustFrida 七天复现教程（修订版）

## 前置：已解决的问题

注入方式：Zygisk + config.json → libagent.so 在 app 进程内直接运行
因此 **Host 端 ptrace attach 这条路不走**，改为：
- SO 被 Zygisk 加载进 app 进程
- SO 内部通过 Unix Socket 与外部工具通信
- 内部追踪使用 gumlibc 直接 syscall（自追踪子线程，不是外部 attach）

## 核心设计决策（修订）

**Native Hook 方式改为：KPM 硬件断点（无痕）**

原始 inline hook 流程：
```
r-xp 代码页 → mprotect(rwxp) → 写字节 → /proc/maps 出现 rwxp 特征 → 暴露
```

修订后：通过 xiaojiahide KPM 的 `prctl(0x45789)` 接口，在内核用硬件执行断点拦截：
```
r-xp 代码页 → 不修改 → 内核 HW_BREAKPOINT_X → CPU 触发时重定向 PC → 无任何痕迹
```

---

## 架构全图（修订版）

```
[外部工具 rust_frida CLI]
        │ abstract Unix Socket "rust_frida_socket"
        │ 命令："nativehook <addr> <replace>", "jhook <class> <method>", "loadjs <code>"
        ▼
[libagent.so] ← 由 Zygisk 加载进 app 进程
        │
        ├── gumlibc：ARM64 直接 syscall（svc 0x0，绕过 libc hook）
        ├── relocater：ARM64 PC 相对指令重定位（用于 trace 模式）
        ├── trace：JIT 代码追踪引擎（基本块转换）
        ├── jhook：ART Java Hook（替换 entry_point_from_compiled_code）
        ├── hwbp_client：prctl(0x45789) → 委托内核注册硬件断点
        └── quickjs_loader：JavaScript 脚本引擎
                │
                │ prctl(0x45789, func_addr, replace_addr, tid)
                ▼
        [xiaojiahide.kpm] ← KernelPatch 内核模块
                ├── register_user_hw_breakpoint (HW_BREAKPOINT_X)
                │   CPU 执行到 func_addr → 触发断点 → 修改 PC = replace_addr
                │   代码页全程保持 r-xp，无任何权限变化
                ├── proc_pid_maps_op->show hook：过滤 rwxp 匿名段（ExecMem 残留）
                ├── do_task_stat hook：隐藏 TracerPid / 't' 状态
                └── /proc/pid/wchan hook：隐藏 ptrace_stop
```

---

## Day 1：项目骨架 + Unix Socket 通信

### 目标
能让 Zygisk 加载 libagent.so，agent 启动 socket 服务器，外部工具连上后收到 "HELLO_AGENT"。

### 环境准备

```bash
# 安装 Rust Android 目标
rustup target add aarch64-linux-android

# 安装 NDK 工具链（假设 NDK 在 ~/Android/Sdk/ndk/27.x.x）
# 配置 ~/.cargo/config.toml
[target.aarch64-linux-android]
linker = "~/Android/Sdk/ndk/27.x.x/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang"
```

```toml
# Cargo.toml
[package]
name = "agent"
crate-type = ["cdylib"]

[dependencies]
libc = "0.2"
jni = "0.21"
```

### 核心代码：lib.rs 骨架

```rust
// src/lib.rs

use std::sync::OnceLock;
use std::os::unix::net::UnixStream;
use std::io::{Write, BufRead, BufReader};
use std::thread;

static GLOBAL_STREAM: OnceLock<std::sync::Mutex<UnixStream>> = OnceLock::new();
const SOCKET_NAME: &str = "rust_frida_socket";  // abstract socket

// ─── ExecMem：RWX 可执行内存管理 ───────────────────────────────────────
pub struct ExecMem {
    ptr: *mut u8,
    size: usize,
    used: usize,
    page_size: usize,
}

impl ExecMem {
    pub fn new() -> Self {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        let size = page_size * 16;  // 初始分配 16 页
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1, 0,
            ) as *mut u8
        };
        assert!(!ptr.is_null());
        Self { ptr, size, used: 0, page_size }
    }

    pub fn write(&mut self, data: &[u8]) -> *mut u8 {
        let dst = unsafe { self.ptr.add(self.used) };
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len()); }
        self.used += data.len();
        dst
    }

    pub fn write_u32(&mut self, value: u32) -> *mut u8 {
        self.write(&value.to_le_bytes())
    }

    pub fn current_addr(&self) -> usize {
        unsafe { self.ptr.add(self.used) as usize }
    }

    pub fn reset(&mut self) { self.used = 0; }
}

// ─── Socket 通信 ──────────────────────────────────────────────────────
fn connect_socket() -> Option<UnixStream> {
    // abstract socket 以 \0 开头
    let mut addr = [0u8; 108];
    let name = SOCKET_NAME.as_bytes();
    addr[0] = 0;
    addr[1..=name.len()].copy_from_slice(name);

    // 使用 UnixStream 连接
    // TODO: 实现 abstract namespace socket 连接
    None  // Day 1 先用占位
}

pub fn log_msg(msg: &str) {
    if let Some(mutex) = GLOBAL_STREAM.get() {
        if let Ok(mut stream) = mutex.lock() {
            let _ = stream.write_all(format!("{}\n", msg).as_bytes());
        }
    }
}

// ─── 命令处理 ─────────────────────────────────────────────────────────
fn process_cmd(command: &str) {
    let mut parts = command.split_whitespace();
    match parts.next() {
        Some("trace") => {
            let tid: i32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            log_msg(&format!("trace not implemented yet, tid={}", tid));
        }
        Some("jhook") => {
            log_msg("jhook not implemented yet");
        }
        Some("jsinit") => {
            log_msg("jsinit not implemented yet");
        }
        Some("loadjs") => {
            let script = parts.remainder().unwrap_or("");
            log_msg(&format!("loadjs: {}", script));
        }
        _ => {
            log_msg(&format!("unknown command: {}", command));
        }
    }
}

// ─── Agent 入口点 ─────────────────────────────────────────────────────
#[no_mangle]
pub extern "C" fn JNI_OnLoad(vm: jni::JavaVM, _: *mut std::ffi::c_void) -> jni::sys::jint {
    thread::spawn(|| {
        agent_main();
    });
    jni::sys::JNI_VERSION_1_6
}

fn agent_main() {
    // 连接 socket，发送 HELLO，进入命令循环
    // 实际实现在 Day 1 完成
    log_msg("HELLO_AGENT");
}
```

### 学习重点
- `crate-type = ["cdylib"]` → 输出 `.so`
- `JNI_OnLoad` 是 SO 被 dlopen 时的入口
- abstract Unix socket（名字以 `\0` 开头）用于跨进程通信
- `mmap(PROT_READ|WRITE|EXEC, MAP_ANONYMOUS)` → RWX 内存

### 优化点
- ExecMem 应该支持动态扩容（目前 `assert!` 溢出会 crash）
- Socket 连接应有重试机制（Zygisk 加载后目标进程可能还没就绪）

---

## Day 2：直接 Syscall（gumlibc.rs）

### 目标
用 ARM64 内联汇编直接触发 syscall，绕过 libc 层的任何 hook/检测。

### 为什么需要直接 syscall

| 方式 | 风险 |
|------|------|
| `libc::ptrace()` | libc 可被 hook，调用栈暴露 |
| 直接 `svc 0x0` | 无 libc 栈帧，绕过 PLT hook |

### 核心代码：gumlibc.rs

```rust
// src/gumlibc.rs
use libc::{c_long, c_void, pid_t};
use std::arch::asm;

// ARM64 syscall: x8=number, x0-x3=args, returns x0
#[inline(always)]
pub fn gum_libc_syscall_4(n: c_long, a: usize, b: usize, c: usize, d: usize) -> usize {
    let result: usize;
    unsafe {
        asm!(
            "svc 0x0",
            in("x8") n,
            inout("x0") a => result,
            in("x1") b,
            in("x2") c,
            in("x3") d,
            options(nostack),
        )
    }
    result
}

// 系统调用号（ARM64 Linux）
pub const SYS_PTRACE: c_long   = 117;
pub const SYS_WAITPID: c_long  = 260;  // wait4
pub const SYS_KILL: c_long     = 129;
pub const SYS_CLONE: c_long    = 220;
pub const SYS_MMAP: c_long     = 222;
pub const SYS_MPROTECT: c_long = 226;

pub fn gum_libc_ptrace(request: i32, pid: i32, addr: usize, data: usize) -> i32 {
    gum_libc_syscall_4(SYS_PTRACE, request as usize, pid as usize, addr, data) as i32
}

pub fn gum_libc_waitpid(pid: i32, status: *mut i32, options: i32) -> i32 {
    gum_libc_syscall_4(SYS_WAITPID, pid as usize, status as usize, options as usize, 0) as i32
}

pub fn gum_libc_kill(pid: i32, sig: i32) -> i32 {
    gum_libc_syscall_4(SYS_KILL, pid as usize, sig as usize, 0, 0) as i32
}

// clone 用于在进程内创建隐藏线程（不过 pthread_create 通常够用）
pub unsafe fn gum_libc_clone(
    child_func: extern "C" fn() -> !,
    flags: u64,
    child_stack: *mut u8,
) -> pid_t {
    let result: pid_t;
    asm!(
        "svc 0x0",
        "cbnz x0, 1f",     // parent: skip child code
        "blr x1",           // child: call child_func（x1 = child_func）
        "mov x8, #93",      // SYS_exit
        "svc 0x0",
        "1:",
        in("x8") SYS_CLONE,
        inout("x0") flags as usize => _,
        in("x1") child_func as usize,
        in("x2") child_stack as usize,
        lateout("x0") result,
    );
    result
}
```

### 学习重点
- ARM64 syscall ABI：x8=调用号，x0=返回值，x0-x5=参数
- `options(nostack)` 告诉编译器汇编块不修改栈
- `inout` 语法：输入用 `a`，输出用 `result`

### 优化点
- 可以封装为宏减少重复代码
- 加入 errno 支持（当前直接返回 raw 值）
- 某些 ROM 对 `/proc/self/task` 枚举有保护，可以用 clone 代替

---

## Day 3：ARM64 指令重定位（relocater.rs）

### 目标
能把任意 ARM64 函数的前 N 条指令复制到新地址，并正确修正 PC 相对偏移。

### 为什么需要重定位

Hook 的基本流程：
```
原始函数 func:
  insn0  ← 要覆写为跳转
  insn1
  insn2

Trampoline（新地址）:
  insn0' ← 重定位后的 insn0（PC 相对偏移已修正）
  insn1'
  insn2'
  JMP back to insn3
```

### 核心知识：哪些指令含 PC 相对偏移

| 指令 | 偏移字段 | 范围 | 用途 |
|------|---------|------|------|
| B / BL | imm26 | ±128MB | 无条件跳转/调用 |
| B.cond | imm19 | ±1MB | 条件跳转 |
| CBZ/CBNZ | imm19 | ±1MB | 比较后跳转 |
| TBZ/TBNZ | imm14 | ±32KB | 位测试后跳转 |
| ADR | imm21 | ±1MB | 计算当前 PC 附近地址 |
| ADRP | imm21*4K | ±4GB | 计算页对齐地址 |
| LDR literal | imm19 | ±1MB | 从 PC 相对地址加载 |

### 核心代码：relocater.rs

```rust
// src/relocater.rs

pub enum RelocStatus {
    Patched,               // 已成功重定位
    UnchangedNotPcRel,     // 非 PC 相对指令，直接复制即可
    UnchangedOutOfRange,   // 超出编码范围，需要更长的序列
}

// ─── 位操作工具 ────────────────────────────────────────────────────────
#[inline] fn get_bits(x: u32, hi: u32, lo: u32) -> u32 {
    (x >> lo) & ((1 << (hi - lo + 1)) - 1)
}

#[inline] fn set_bits(orig: u32, hi: u32, lo: u32, v: u32) -> u32 {
    let mask = ((1u32 << (hi - lo + 1)) - 1) << lo;
    (orig & !mask) | ((v << lo) & mask)
}

#[inline] fn sign_extend(value: usize, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value as i64) << shift) >> shift
}

#[inline] fn fits_signed(v: i64, bits: u32) -> bool {
    let min = -(1i64 << (bits - 1));
    let max = (1i64 << (bits - 1)) - 1;
    v >= min && v <= max
}

// ─── 主重定位函数 ──────────────────────────────────────────────────────
pub unsafe fn relocate_one_a64(src: usize, dst: usize) -> RelocStatus {
    let insn: u32 = core::ptr::read_volatile(src as *const u32);

    // 按指令编码模式匹配（从最宽泛到最精确）
    if let Some(result) = try_b_bl(src, dst, insn) { return apply(dst, insn, result); }
    if let Some(result) = try_b_cond(src, dst, insn) { return apply(dst, insn, result); }
    if let Some(result) = try_cbz_cbnz(src, dst, insn) { return apply(dst, insn, result); }
    if let Some(result) = try_tbz_tbnz(src, dst, insn) { return apply(dst, insn, result); }
    if let Some(result) = try_adr(src, dst, insn) { return apply(dst, insn, result); }
    if let Some(result) = try_adrp(src, dst, insn) { return apply(dst, insn, result); }
    if let Some(result) = try_ldr_literal(src, dst, insn) { return apply(dst, insn, result); }

    // 非 PC 相对指令，直接原样复制
    core::ptr::write_volatile(dst as *mut u32, insn);
    RelocStatus::UnchangedNotPcRel
}

fn apply(dst: usize, orig: u32, patched: Option<u32>) -> RelocStatus {
    match patched {
        Some(insn) => {
            unsafe { core::ptr::write_volatile(dst as *mut u32, insn); }
            RelocStatus::Patched
        }
        None => {
            // OutOfRange：先原样写入（后续由调用方决定如何展开）
            unsafe { core::ptr::write_volatile(dst as *mut u32, orig); }
            RelocStatus::UnchangedOutOfRange
        }
    }
}

// ─── B / BL（imm26，bit31 区分 BL）──────────────────────────────────────
fn try_b_bl(src: usize, dst: usize, insn: u32) -> Option<Option<u32>> {
    // 编码：[31]=1(BL)/0(B), [30:26]=00101, [25:0]=imm26
    if (insn & 0x7C00_0000) != 0x1400_0000 { return None; }

    let imm26 = get_bits(insn, 25, 0) as usize;
    let target = ((src as i64) + sign_extend(imm26, 26) * 4) as usize;
    let new_off = (target as i64) - (dst as i64);

    if !fits_signed(new_off / 4, 26) { return Some(None); }
    let new_imm26 = ((new_off / 4) as u32) & 0x03FF_FFFF;
    Some(Some(set_bits(insn, 25, 0, new_imm26)))
}

// ─── B.cond（imm19）────────────────────────────────────────────────────
fn try_b_cond(src: usize, dst: usize, insn: u32) -> Option<Option<u32>> {
    if (insn & 0xFF00_001F) != 0x5400_0000 { return None; }  // 判断是 B.cond

    let imm19 = get_bits(insn, 23, 5) as usize;
    let target = ((src as i64) + sign_extend(imm19, 19) * 4) as usize;
    let new_off = (target as i64) - (dst as i64);

    if !fits_signed(new_off / 4, 19) { return Some(None); }
    let new_imm19 = ((new_off / 4) as u32) & 0x0007_FFFF;
    Some(Some(set_bits(insn, 23, 5, new_imm19)))
}

// CBZ/CBNZ、TBZ/TBNZ、ADR、ADRP、LDR literal 类似实现...

// ─── 展开 OutOfRange 的 B/BL 为长跳转序列 ──────────────────────────────
// 当 B target 超出 ±128MB，需要展开为：
//   LDR x16, #8
//   BR x16 (或 BLR x16 用于 BL)
//   .quad target
pub fn gen_long_jump(target: usize, is_call: bool) -> Vec<u32> {
    // LDR x16, #8 = 0x5800_0050（PC+8 处加载）
    // BR x16      = 0xD61F_0200
    // BLR x16     = 0xD63F_0200
    // 然后是 8 字节的 target 地址（拆成两个 u32）
    vec![
        0x5800_0050u32,  // LDR x16, #8
        if is_call { 0xD63F_0200 } else { 0xD61F_0200 },
        (target & 0xFFFF_FFFF) as u32,
        (target >> 32) as u32,
    ]
}
```

### 学习重点
- ARM64 指令是 32 位定长，大端序存储位字段
- ADRP 最特殊：偏移以 4KB 页为单位，`target = PC & ~0xFFF + imm21 * 4096`
- OutOfRange 时需要展开为 `LDR x16, #8; BR x16; .quad addr`（12 或 16 字节）

### 优化点
- ADRP 展开后通常与后面的 `ADD` / `LDR` 配对，应该作为指令对处理
- 可以缓存重定位结果（同一函数多次 trace 时复用）

---

## Day 4：无痕 Native Hook（KPM 硬件断点）

### 目标
通过 xiaojiahide KPM 的 prctl 接口，在内核注册硬件执行断点，实现对 native 函数的 hook，
**全程不修改代码页字节，不产生 rwxp 内存，/proc/maps 无任何异常特征**。

### 两种 Native Hook 方案对比

| 方案 | 代码页权限变化 | /proc/maps 特征 | ARM64 限制 |
|------|-------------|----------------|-----------|
| 传统 inline hook | r-xp → 写入 → rwxp 残留 | `rwxp 00000000 00:00` 暴露 | 无 |
| **KPM 硬件断点（选用）** | r-xp 全程不变 | 无异常 | 最多 6 个断点 |

### 工作原理

```
prctl(0x45789, func_addr, replace_fn, tid, 0)
        │
        ▼ (xiaojiahide KPM 内核态)
register_user_hw_breakpoint(
    attr.bp_type = HW_BREAKPOINT_X,   // 执行断点
    attr.bp_addr = func_addr,
    handler = hw_bp_handler
)
        │
        ▼ (CPU 执行到 func_addr 时)
hw_bp_handler(regs):
    regs->pc = replace_fn             // 重定向 PC，不修改任何代码
```

### 核心代码：hwbp_client.rs

```rust
// src/hwbp_client.rs
// 通过 prctl 与 xiaojiahide KPM 通信

const HWBP_HOOK_OPTION:    i32 = 0x45789;  // prctl option：注册断点 hook
const HWBP_CLEAR_ALL:      i32 = 0x45788;  // prctl option：清除所有断点
const HWBP_CLEAR_ONE:      i32 = 0x45787;  // prctl option：清除单个断点

// ─── 注册硬件断点 hook ────────────────────────────────────────────────
pub fn hw_hook(func_addr: usize, replace_addr: usize, tid: i32) -> Result<(), String> {
    let ret = unsafe {
        libc::prctl(HWBP_HOOK_OPTION, func_addr, replace_addr, tid as usize, 0)
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!("hw_hook failed: errno={}", std::io::Error::last_os_error()))
    }
}

// ─── 清除单个断点 ──────────────────────────────────────────────────────
pub fn hw_unhook(func_addr: usize, tid: i32) -> Result<(), String> {
    let ret = unsafe {
        libc::prctl(HWBP_CLEAR_ONE, func_addr, tid as usize, 0, 0)
    };
    if ret > 0 { Ok(()) } else { Err("hw_unhook failed".to_string()) }
}

// ─── 清除所有断点 ──────────────────────────────────────────────────────
pub fn hw_unhook_all() {
    unsafe { libc::prctl(HWBP_CLEAR_ALL, 0, 0, 0, 0); }
}

// ─── replace_fn 的函数签名约定 ────────────────────────────────────────
// replace_fn 被调用时，寄存器状态与 func_addr 被调用时完全一致
// 若需要调用原始函数，需要另行实现 trampoline（Day 3 的重定位技术）
// 或接受"替换而非拦截"语义（不调用原始函数）

// ─── 命令处理集成 ─────────────────────────────────────────────────────
pub fn handle_nativehook_cmd(args: &str) -> String {
    // 格式：nativehook <func_addr_hex> <replace_addr_hex> [tid]
    let mut parts = args.split_whitespace();
    let func_addr = parse_hex(parts.next().unwrap_or("0"));
    let replace_addr = parse_hex(parts.next().unwrap_or("0"));
    let tid: i32 = parts.next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(unsafe { libc::gettid() });

    match hw_hook(func_addr, replace_addr, tid) {
        Ok(()) => format!("hw_hook ok: func={:#x} replace={:#x} tid={}", func_addr, replace_addr, tid),
        Err(e) => format!("hw_hook err: {}", e),
    }
}

fn parse_hex(s: &str) -> usize {
    usize::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0)
}
```

### replace_fn 的设计模式

由于硬件断点 hook 是"替换"而非"拦截"（replace_fn 被调用时原函数不再执行），
有两种用法：

**模式 A：纯替换（最简单）**
```rust
// replace_fn 完整替代原函数逻辑
extern "C" fn my_replace(arg0: usize, arg1: usize) -> usize {
    log_msg(&format!("hooked! arg0={:#x}", arg0));
    // 执行自己的逻辑，不调用原函数
    0
}
```

**模式 B：拦截 + 调用原函数（需要 trampoline）**
```rust
// 在 ExecMem 中构建 trampoline（复制原函数前 N 字节 + 跳回）
// replace_fn 调用 trampoline，trampoline 执行原始逻辑后返回
static TRAMPOLINE_ADDR: AtomicUsize = AtomicUsize::new(0);

extern "C" fn my_intercept(arg0: usize, arg1: usize) -> usize {
    log_msg(&format!("before: arg0={:#x}", arg0));

    // 调用原始函数（通过 Day 3 构建的 trampoline）
    let orig_fn: extern "C" fn(usize, usize) -> usize =
        unsafe { std::mem::transmute(TRAMPOLINE_ADDR.load(Ordering::Relaxed)) };
    let ret = orig_fn(arg0, arg1);

    log_msg(&format!("after: ret={:#x}", ret));
    ret
}
```

### 学习重点
- `HW_BREAKPOINT_X` 是**执行断点**，与调试器的 `HW_BREAKPOINT_W`（写断点）不同
- ARM64 PMU 提供 6 个硬件断点槽（BCR0-BCR5 / BVR0-BVR5）
- `attr.inherit_thread = 1` 使 fork 出的子线程自动继承断点
- KPM 的 ptrace hook 会拦截调试器的 `PTRACE_GETREGSET NT_ARM_HW_BREAK` 查询，返回伪造值

### 优化点
- 硬件断点有数量上限（6 个），优先 hook 关键入口点
- 超出 6 个时降级为 inline hook（接受 rwxp 暴露，由 KPM /proc/maps 过滤兜底）
- trampoline 构建放在 ExecMem 中（即使 rwxp，也会被 KPM 过滤）

---

## Day 5：代码追踪引擎（trace.rs 核心）

### 目标
实现线程内指令级追踪（基本块转换），能在每条指令执行前/后插入回调。

### 两种追踪思路

| 方式 | 原理 | 侵入性 |
|------|------|--------|
| ptrace SINGLESTEP | 每条指令触发 SIGTRAP | 高（暂停线程） |
| **代码转换（JIT trace）** | 复制基本块+插桩，让线程直接运行 | 低（线程继续运行） |

rustFrida 用的是**代码转换**方案（类似 Frida Stalker）。

### 核心概念：基本块转换

```
原始基本块：
  addr_0: insn0   <- 入口
  addr_4: insn1
  addr_8: B target  <- 出口（分支）

转换后（ExecMem 中）：
  cb_0: CALL on_insn_enter(addr_0)  <- 插桩点
  cb_4: insn0'  (重定位)
  cb_8: CALL on_insn_enter(addr_4)
  cb_C: insn1'
  cb_10: CALL resolve_and_jump(target)  <- 出口时解析下个基本块
```

### 核心代码框架

```rust
// src/trace.rs

use crate::relocater::relocate_one_a64;
use crate::gumlibc::{gum_libc_ptrace, SYS_PTRACE};

// 追踪会话
pub struct TraceSession {
    pub tid: i32,
    pub block_cache: std::collections::HashMap<usize, usize>,  // orig_addr -> translated_addr
}

// ─── 枚举当前进程的所有线程 ────────────────────────────────────────────
pub fn list_threads() -> Vec<i32> {
    let mut tids = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc/self/task") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(tid) = name.parse::<i32>() {
                    tids.push(tid);
                }
            }
        }
    }
    tids
}

// ─── 分析下一条指令地址（处理分支）─────────────────────────────────────
pub unsafe fn resolve_next_addr(pc: usize, regs: &UserRegs) -> Vec<usize> {
    let insn = core::ptr::read_volatile(pc as *const u32);

    // 无条件跳转 B
    if (insn & 0xFC00_0000) == 0x1400_0000 {
        let off = sign_extend((insn & 0x03FF_FFFF) as usize, 26) * 4;
        return vec![(pc as i64 + off) as usize];
    }

    // BL（调用，下一条是 PC+4，但目标也要追踪）
    if (insn & 0xFC00_0000) == 0x9400_0000 {
        let off = sign_extend((insn & 0x03FF_FFFF) as usize, 26) * 4;
        return vec![(pc as i64 + off) as usize];
    }

    // B.cond（两个出口）
    if (insn & 0xFF00_001F) == 0x5400_0000 {
        let off = sign_extend(get_bits(insn, 23, 5) as usize, 19) * 4;
        let taken = (pc as i64 + off) as usize;
        let not_taken = pc + 4;
        return vec![taken, not_taken];
    }

    // BR/RET（间接，从寄存器读目标）
    if (insn & 0xFFFF_FC1F) == 0xD61F_0000 {
        let reg = get_bits(insn, 9, 5) as usize;
        return vec![regs.regs[reg]];
    }

    // 默认：顺序执行
    vec![pc + 4]
}

// ─── 转换一个基本块 ────────────────────────────────────────────────────
pub unsafe fn translate_basic_block(
    orig_addr: usize,
    exec: &mut ExecMem,
    on_enter: Option<usize>,  // 插桩回调函数地址（可选）
) -> usize {
    let translated_start = exec.current_addr();
    let mut pc = orig_addr;

    loop {
        let insn = core::ptr::read_volatile(pc as *const u32);
        let dst = exec.current_addr();

        // 可选：插入回调指令（保存/恢复寄存器 + BLR x_callback）
        // ...（需要保存所有寄存器的 stub）

        // 重定位当前指令
        relocate_one_a64(pc, dst);
        exec.used += 4;

        // 判断是否为分支指令（基本块出口）
        if is_branch(insn) {
            // 追加：跳转到 transformer，解析下一个基本块
            // gen_long_jump(transformer_addr) ...
            break;
        }
        pc += 4;
    }

    translated_start
}

fn is_branch(insn: u32) -> bool {
    // B, BL, B.cond, CBZ, CBNZ, TBZ, TBNZ, BR, BLR, RET
    matches!(insn & 0xFC00_0000, 0x1400_0000 | 0x9400_0000)
    || (insn & 0xFF00_001F) == 0x5400_0000
    || (insn & 0xFE00_0000) == 0x3400_0000  // CBZ/CBNZ
    || (insn & 0xFE00_0000) == 0x3600_0000  // TBZ/TBNZ
    || (insn & 0xFFFF_FC1F) == 0xD61F_0000  // BR
    || (insn & 0xFFFF_FC1F) == 0xD63F_0000  // BLR
    || insn == 0xD65F_03C0                   // RET
}
```

### 学习重点
- 基本块以**第一个分支指令**为结尾
- 间接分支（BR/BLR/RET）的目标地址只有运行时才知道，需要实时解析
- 需要 Block Cache 避免重复翻译同一基本块

### 优化点
- Block Cache 应该加锁（多线程同时追踪时）
- 超过某大小的基本块可以只追踪前 N 条指令

---

## Day 6：ART Java Hook（jhook.rs）

### 目标
不依赖 frida/JVMTI，直接操作 ART Runtime 内存，
替换 `ArtMethod.entry_point_from_compiled_code` 实现 Java 方法 hook。

### 为什么不用 JVMTI

| 方式 | 检测风险 | 稳定性 |
|------|---------|--------|
| JVMTI Agent attach | `agent.jar` / socket 特征暴露 | 好 |
| **直接操作 ArtMethod（选用）** | 无特征 | 需版本适配 |

### ART 内存结构（调用链）

```
JavaVM*  (用户代码持有的指针)
  └─ functions = JNIInvokeInterface_*
       └─ reserved0 = Runtime*          ← 关键入口
            └─ [偏移 N] = ClassLinker*
                 └─ VisitClasses(ClassVisitor*)  ← 枚举所有已加载 Class
                      └─ mirror::Class::GetMethodsPtr()
                           └─ ArtMethod[]
                                └─ entry_point_from_compiled_code  ← Hook 这里
```

### ArtMethod 内存布局（ARM64，偏移按 API 级别变化）

```
ArtMethod（每个 Java 方法对应一个）：
  +0x00  declaring_class              u32  (GC compressed ref)
  +0x04  access_flags                 u32  (public/private/native 等)
  +0x08  dex_method_index             u32
  +0x0C  method_index                 u16
  +0x0E  imt_index / hotness_count    u16
  ...
  +0x28  data_ / entry_point_from_jni usize  (native 方法指向 JNI 实现)
  +0x30  entry_point_from_compiled_code usize  ← 替换这里
         正常指向 OAT 编译的机器码
         替换为我们的 hook_fn 后，调用该 Java 方法时直接跳到 hook_fn
```

### 核心代码

```rust
// src/jhook.rs

use std::collections::HashMap;
use std::ffi::CString;
use std::sync::OnceLock;

// ArtMethod 中 entry_point_from_compiled_code 的偏移（随 Android 版本变化）
fn entry_point_offset(api: i32) -> usize {
    match api {
        ..=28  => 0x28,  // Android 9 及以下
        29..=30 => 0x30, // Android 10-11
        31..=32 => 0x30, // Android 12
        33..    => 0x30, // Android 13+（需要实测确认）
        _      => 0x30,
    }
}

// ClassLinker 在 Runtime 对象中的偏移
fn class_linker_offset(api: i32) -> usize {
    match api {
        ..=27  => 456,
        28     => 460,
        29..=30 => 480,
        31..=32 => 488,
        33..    => 504,
        _      => 504,
    }
}

pub struct ArtHook {
    pub artmethod_ptr: usize,
    pub original_entry: usize,
}

// ─── 主入口 ──────────────────────────────────────────────────────────────
pub unsafe fn jhook(
    vm: *mut jni::sys::JavaVM,
    target_class: &str,   // "com/example/App"
    target_method: &str,  // "secretMethod"
    hook_fn: usize,       // 替换函数地址
) -> Result<ArtHook, String> {
    let api = get_api_level();

    // 1. 通过 JavaVM 找到 Runtime*
    // JavaVM.functions = JNIInvokeInterface_
    // JNIInvokeInterface_.reserved0 = Runtime*
    let jni_invoke = *vm;           // JNIInvokeInterface_*
    let runtime_ptr = (*jni_invoke).reserved0 as usize;
    if runtime_ptr == 0 {
        return Err("runtime_ptr is null".into());
    }

    // 2. 找到 ClassLinker*
    let cl_offset = class_linker_offset(api);
    let class_linker = *(runtime_ptr + cl_offset) as *mut usize;
    if class_linker.is_null() {
        return Err("ClassLinker is null".into());
    }

    // 3. 加载 libart.so，解析符号
    let libart = libc::dlopen(c"libart.so".as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD);
    if libart.is_null() {
        return Err("dlopen libart.so failed".into());
    }

    // 4. 通过 JNI 找到目标 Class 和 Method（利用已有的 JNIEnv）
    let mut env: *mut jni::sys::JNIEnv = std::ptr::null_mut();
    (**vm).AttachCurrentThread.unwrap()(
        vm, &mut env as *mut _ as *mut _, std::ptr::null_mut()
    );

    let class_name_c = CString::new(target_class).unwrap();
    let jclass = (**env).FindClass.unwrap()(env, class_name_c.as_ptr());
    if jclass.is_null() {
        return Err(format!("FindClass {} failed", target_class));
    }

    // 通过 JNI GetMethodID 找到 jmethodID
    // jmethodID 在 ART 中就是 ArtMethod* 的包装
    let method_name_c = CString::new(target_method).unwrap();
    let sig_c = CString::new("()V").unwrap();  // 需要调用方提供真实签名
    let jmethod = (**env).GetMethodID.unwrap()(
        env, jclass, method_name_c.as_ptr(), sig_c.as_ptr()
    );
    if jmethod.is_null() {
        return Err(format!("GetMethodID {} failed", target_method));
    }

    // jmethodID 就是 ArtMethod*（art/runtime/jni/jni_internal.cc: jmethodID = ArtMethod*）
    let artmethod_ptr = jmethod as usize;

    // 5. 读取原始 entry_point，写入新的 hook_fn
    let ep_offset = entry_point_offset(api);
    let ep_addr = (artmethod_ptr + ep_offset) as *mut usize;
    let original_entry = *ep_addr;

    // 原子写入（防止并发调用期间读到半写状态）
    std::ptr::write_volatile(ep_addr, hook_fn);

    // 6. 禁止 JIT 重编译覆盖我们的 hook
    //    将 hotness_count 设为 0，使 ART 认为该方法不热
    //    更强的保护：设置 access_flags 的 kAccPreCompiled 位
    let access_flags_addr = (artmethod_ptr + 0x04) as *mut u32;
    let flags = *access_flags_addr;
    // kAccPreCompiled (0x00800000) 阻止 JIT 重编译
    *access_flags_addr = flags | 0x0080_0000;

    crate::log_msg(&format!(
        "jhook ok: {}#{} artmethod={:#x} orig_entry={:#x} hook_fn={:#x}",
        target_class, target_method, artmethod_ptr, original_entry, hook_fn
    ));

    Ok(ArtHook { artmethod_ptr, original_entry })
}

// ─── 还原 hook ────────────────────────────────────────────────────────────
pub unsafe fn junhook(hook: &ArtHook, api: i32) {
    let ep_offset = entry_point_offset(api);
    let ep_addr = (hook.artmethod_ptr + ep_offset) as *mut usize;
    std::ptr::write_volatile(ep_addr, hook.original_entry);
}

// ─── hook_fn 调用原始方法的方式 ──────────────────────────────────────────
// hook_fn 替换了 entry_point，所以调用 Java 方法会直接跳入 hook_fn
// hook_fn 的调用约定与 ART 的 Quick ABI 一致：
//   x0 = ArtMethod*
//   x1 = this (jobject, 实例方法)
//   x2.. = 参数
//
// 若需要调用原始实现，直接跳转到 original_entry：
pub extern "C" fn example_hook(
    art_method: *mut usize,
    this: *mut usize,
    arg0: i32,
) -> i32 {
    crate::log_msg(&format!("java method hooked! this={:?} arg0={}", this, arg0));

    // 调用原始实现（需要从 ArtHook 获取 original_entry）
    let original: extern "C" fn(*mut usize, *mut usize, i32) -> i32 =
        unsafe { std::mem::transmute(ORIGINAL_ENTRY.load(Ordering::Relaxed)) };
    original(art_method, this, arg0)
}

fn get_api_level() -> i32 {
    // 读取 system property ro.build.version.sdk
    // 简化实现：从 /proc/sys/kernel/osrelease 推断，或 hardcode
    if let Ok(s) = std::fs::read_to_string("/system/build.prop") {
        for line in s.lines() {
            if line.starts_with("ro.build.version.sdk=") {
                return line[21..].trim().parse().unwrap_or(33);
            }
        }
    }
    33
}
```

### 关键细节

**jmethodID = ArtMethod\* 的依据：**
ART 内部实现 `jmethodID` 就是指向 `ArtMethod` 对象的指针，不需要额外解引用。
这是 AOSP 代码中 `art/runtime/jni/jni_internal.cc` 的既定实现，所有版本一致。

**JIT 重编译覆盖问题：**
ART 的 JIT 编译器可能在后台重新编译热点方法，覆盖 `entry_point_from_compiled_code`。
两种防护：
1. `hotness_count = 0` → 方法不热，JIT 不主动编译（弱保护）
2. 设置 `kAccPreCompiled` 标志 → ART 认为已有 AOT 编译结果，跳过 JIT（强保护）

**Hook fn 调用约定（Quick ABI）：**
ART Quick 调用约定：
- x0 = ArtMethod*（总是隐式第一参数）
- x1 = this（实例方法）或第一个参数（静态方法）
- x2.. = 剩余参数
- 返回值在 x0（int/ref）或 d0（float/double）

### 学习重点
- `jmethodID` 就是 `ArtMethod*`，无需符号解析
- ClassLinker 偏移每个 AOSP 版本可能不同，建议用 InternTable 地址辅助定位
- Quick ABI 与 JNI 调用约定不同，hook_fn 参数顺序要对

### 优化点
- 用符号扫描确认 ClassLinker 偏移（而非硬编码）
- 支持 hook static 方法（x1 开始是参数，无 this）
- 批量 hook 同一类的多个方法（复用 jclass 查询结果）

---

## Day 7：QuickJS 集成 + Host 工具 + 联调

### 目标
Agent 支持执行 JavaScript 脚本（类 Frida 体验），Host 工具可以交互式发送脚本。

### QuickJS 集成（quickjs_loader.rs）

```rust
// src/quickjs_loader.rs
// 依赖 quickjs-hook crate（项目已有）

use quickjs_hook::{JsEngine, load_script};

static JS_ENGINE: OnceLock<Mutex<Option<JsEngine>>> = OnceLock::new();

pub fn init() -> Result<(), String> {
    let engine = JsEngine::new()
        .map_err(|e| format!("QuickJS init failed: {:?}", e))?;

    // 注册 Frida 兼容的 API
    engine.add_global_function("send", js_send);        // 发送数据到 host
    engine.add_global_function("recv", js_recv);        // 从 host 接收数据
    engine.add_global_function("console.log", js_log);  // 日志

    JS_ENGINE.get_or_init(|| Mutex::new(Some(engine)));
    Ok(())
}

pub fn execute_script(code: &str) -> Result<String, String> {
    let guard = JS_ENGINE.get().ok_or("QuickJS not initialized")?;
    let engine = guard.lock().unwrap();
    let engine = engine.as_ref().ok_or("QuickJS cleaned up")?;

    engine.eval(code).map_err(|e| format!("JS error: {:?}", e))
}

// JS send() → 通过 socket 发回 host
extern "C" fn js_send(ctx: *mut JSContext, this: JSValue, argc: i32, argv: *mut JSValue) -> JSValue {
    // 提取参数，发送到 GLOBAL_STREAM socket
    todo!()
}
```

### Host 工具（简化版）

```rust
// rust_frida_host/src/main.rs（简化版，用于 Zygisk 场景）
// 不再需要 ptrace inject，只需要 socket 通信

use std::os::unix::net::UnixListener;
use rustyline::Editor;

fn main() {
    // 1. 监听 abstract socket
    let listener = UnixListener::bind("\0rust_frida_socket").unwrap();
    println!("[*] Waiting for agent to connect...");

    let (stream, _) = listener.accept().unwrap();
    println!("[*] Agent connected!");

    // 2. 读取 HELLO_AGENT
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    println!("[+] {}", line.trim());

    // 3. 交互式 REPL
    let mut rl = Editor::<()>::new().unwrap();
    loop {
        let input = rl.readline("frida> ").unwrap_or_default();
        if input.is_empty() { continue; }

        // 发送命令
        stream.write_all(format!("{}\n", input).as_bytes()).unwrap();

        // 读取响应
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        println!("{}", response.trim());
    }
}
```

### 联调检查清单

```
Day 1: Zygisk 加载 libagent.so → 连接 socket → 收到 "HELLO_AGENT"  ✓
Day 2: 发送命令调用 gum_libc_kill(pid, 0) → 返回 0（进程存在）      ✓
Day 3: 发送目标函数地址 → 返回重定位后的指令序列                    ✓
Day 4: 发送 "hook 0x<addr>" → 函数被 hook，回调触发                 ✓
Day 5: 发送 "trace <tid>" → 收到指令追踪日志                        ✓
Day 6: 发送 "jhook" → Java 方法被 hook，调用时触发                  ✓
Day 7: 发送 "jsinit; loadjs Interceptor.attach(...)" → JS 执行     ✓
```

---

## 优化总览（修订版）

### 架构层面

| 问题 | 优化方向 |
|------|---------|
| ExecMem 固定大小 | 链表分配，支持多块 |
| Block Cache 无淘汰 | LRU Cache，限制内存使用 |
| Socket 协议无帧边界 | 加 length prefix（4 字节长度头） |
| 单线程命令处理 | 多线程 + channel 分发 |
| 硬件断点数量上限（6个） | 超出时降级 inline hook + KPM /proc/maps 过滤兜底 |

### 安全层面（修订）

| 检测手段 | 对抗方式 |
|---------|---------|
| solist 枚举 | zygisk-gadget：hide_utils.cpp 已处理 |
| 线程名特征 | zygisk-gadget：thread_rename.cpp 已处理 |
| TracerPid / 't' 状态 | xiaojiahide KPM：do_task_stat + seq_puts hook |
| /proc/maps 匿名 rwxp | xiaojiahide KPM：proc_pid_maps_op->show 过滤 |
| /proc/maps memfd 名称 | xiaojiahide KPM：hide_err_execute 字符串过滤 |
| JVMTI attach 特征 | jhook 不用 JVMTI，直接操作 ArtMethod |
| Native hook 代码页变化 | **KPM 硬件断点**：代码页全程 r-xp，无变化 |
| /proc/wchan ptrace_stop | xiaojiahide KPM：proc_pid_wchan hook |

### Hook 选型决策树

```
需要 hook 什么？
    │
    ├─ Java 方法 → jhook（替换 ArtMethod.entry_point_from_compiled_code）
    │              + kAccPreCompiled 防 JIT 覆盖
    │
    └─ Native 函数（SO 中）
           │
           ├─ 关键函数（数量 ≤ 6）→ KPM 硬件断点（无痕首选）
           │
           └─ 批量函数（数量 > 6）→ inline hook + KPM /proc/maps 过滤兜底
```

---

## 参考文件索引

| Day | 对应 rustFrida 文件 |
|-----|-------------------|
| 1 | `agent/src/lib.rs:1-200`（ExecMem、socket、JNI_OnLoad） |
| 2 | `agent/src/gumlibc.rs`（全文 76 行） |
| 3 | `agent/src/relocater.rs`（全文 284 行） |
| 4 | `agent/src/writer.rs`（当前为空，需自行实现）|
| 5 | `agent/src/trace.rs`（全文 602 行）|
| 6 | `agent/src/jhook.rs`（全文 234 行）|
| 7 | `agent/src/quickjs_loader.rs`（全文 128 行）、`rust_frida/src/main.rs` |
