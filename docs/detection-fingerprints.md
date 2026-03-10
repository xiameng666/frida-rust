# XiaM Detection Fingerprint Analysis

本文档列出当前注入链中所有可被目标 app / 反作弊系统检测到的特征，按检测难度从易到难排序。

## 🔴 高风险（常规反作弊必查）

### 1. /proc/self/maps — SO 加载 memfd 残留
- ~~hook pool 双映射 `memfd:xiam`~~ → **已消除**: 改为匿名 `mmap(R-X)`，无 memfd
- SO 本体仍通过 memfd 加载（`remote_inject` 中 `memfd_create("xiam")`），maps 中残留 `/memfd:xiam (deleted)` 路径
- maps 由内核维护，**用户态无法删除或修改条目**

**缓解**: SO 加载 memfd 改名为空字符串或伪装名

### 2. /proc/net/unix — 抽象 socket 暴露
- `@xiam_patcher` 抽象 socket 在 `/proc/net/unix` 中可见
- `@xiam_zymbiote` 通知 socket（注入阶段短暂存在）

**缓解**: socket 名改为随机字符串或 UUID

### 3. Logcat — 日志标签暴露
- C 层: `__android_log_print` 使用 tag `XiaM-hook`、`XiaM-hide`
- Rust 层: `eprintln!` 输出 `[XiaM-hook]`、`[XiaM-hide]` 前缀 → stderr → logcat
- 同 UID 的进程可通过 `logcat` 读取这些日志

**缓解**: Release build 通过条件编译完全去除所有日志输出

## 🟡 中等风险

### 4. /proc/self/fd/ — 文件描述符泄露
- ~~hook pool memfd fd~~ → **已消除**: 改为匿名 mmap，无 fd
- SO 加载 memfd fd 未关闭（关闭导致 linker SIGILL）— `readlink` 显示 `memfd:xiam`
- patcher 抽象 socket fd（`@xiam_patcher`）
- TCP socket fd（连接 `127.0.0.1:12708`）

**缓解**: SO memfd 名伪装后 fd 特征降低；关闭不需要的 fd

### 5. /proc/net/tcp — 回环连接
- adb reverse 转发产生 `127.0.0.1:12708` TCP 连接
- 反作弊可扫描 `/proc/net/tcp` 检测异常回环连接

**缓解**: 端口随机化；或改用 abstract socket 替代 TCP

### 6. .rodata 字符串常量（内存扫描）
SO 二进制中包含以下可辨识字符串:
- `"XiaM-hook"`, `"XiaM-hide"` — log tag
- `"xiam"` — SO 加载 memfd 名称（hook pool 已不再使用 memfd）
- `"xiam_patcher"` — socket 名称
- `"hello_entry"` — 导出符号名
- `"/alone12345678"` — stub marker（仅 Zygote 中，注入后已恢复）
- `"memfd"` — so_hide 搜索关键字
- QuickJS 相关字符串（`"quickjs"`, `"eval"`, `"Interceptor"` 等）

**缓解**: 字符串混淆 / 加密；导出符号改名或 strip

## 🟢 低风险（需要高级检测）

### 7. 线程异常
- `pthread_create` 创建的 agent 线程 — `/proc/self/task/` 多出线程
- 线程名可能是默认的 `Thread-N`

**缓解**: 设置伪装线程名（如 `FinalizerDaemon`）

### 8. Inline Hook 代码完整性
- 被 hook 函数的前几条指令被替换为跳转（B/BR 到 trampoline）
- trampoline 代码位于匿名 R-X 映射中（已无 memfd 特征名）
- 代码完整性校验（CRC/hash 比对 .text 段）可检测

**缓解**: 使用 hardware breakpoint 代替 inline patch（需内核支持）

### 9. ELF Header 全零
- SO base 地址处前 64 字节被清零 — 正常 SO 应以 `\x7fELF` 开头
- 内存扫描 maps 中每个映射段的 header 可发现全零异常

**缓解**: 填充为假 ELF header 而非全零

### 10. 行为/时序特征
- **ptrace**: 注入时 `/proc/self/status` TracerPid 非零（短暂可见）
- **Zygote 卡顿**: SIGSTOP/SIGCONT 导致 fork 延迟
- **启动延迟**: setArgV0Native 被拦截，等待注入完成后才继续执行

**缓解**: 缩短注入时间窗口；ptrace 完成后立即 detach

## 已缓解的特征

| 特征 | 缓解措施 | 状态 |
|------|----------|------|
| soinfo 链表中的 SO 信息 | `so_hide.c` 摘除 soinfo 节点 | ✅ 已实现 |
| `_r_debug->r_map` link_map 链 | `so_hide.c` 摘除 link_map 节点 | ✅ 已实现 |
| `dl_iterate_phdr` 枚举可见 | soinfo + link_map 摘除后不再可见 | ✅ 已实现 |
| ELF header 标识 SO 存在 | 64 字节清零（通过 server pwrite） | ✅ 已实现 |
| /proc/self/mem 自身读写 | 改用 server pwrite 代替 | ✅ 已实现 |
| RWX 内存页 | 匿名 mmap R-X + server pwrite（零 RWX） | ✅ 已实现 |
| mprotect 调用 | server pwrite 绕过页面保护，零 mprotect | ✅ 已实现 |
| hook pool memfd 特征 | 去掉 memfd 双映射，改匿名 mmap(R-X) | ✅ 已实现 |

## 下一步优先级

1. **SO 加载 memfd 改名** — `remote_inject` 中 `xiam` 改为空字符串或伪装名
2. **Release 去日志** — 条件编译移除所有 `__android_log_print` 和 `eprintln!`
3. **Socket 随机化** — `@xiam_patcher` 改用运行时生成的随机名称
4. **字符串混淆** — 编译期加密 .rodata 中的敏感字符串
5. **端口随机化** — TCP 12708 改为随机端口
