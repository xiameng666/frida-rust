/*
 * hook_engine.c - ARM64 Inline Hook Engine Implementation
 *
 * Provides inline hooking functionality for ARM64 Android.
 * Uses the arm64_writer and arm64_relocator modules for code generation
 * and instruction relocation.
 */

#include "hook_engine.h"
#include "arm64_writer.h"
#include "arm64_relocator.h"
#include <stdlib.h>
#include <stdio.h>

#ifdef __ANDROID__
#include <android/log.h>
#define HOOK_TAG "XiaM-hook"
#define HOOK_LOGI(...) __android_log_print(ANDROID_LOG_INFO,  HOOK_TAG, __VA_ARGS__)
#define HOOK_LOGW(...) __android_log_print(ANDROID_LOG_WARN,  HOOK_TAG, __VA_ARGS__)
#else
#define HOOK_LOGI(...) fprintf(stderr, "[hook-info] " __VA_ARGS__)
#define HOOK_LOGW(...) fprintf(stderr, "[hook-warn] " __VA_ARGS__)
#endif

/* =========================================================================
 * Raw syscall wrappers + inline libc replacements
 * ÁªïËøá PLT/GOTÔºåÈÅøÂÖçË¢´ libc inline hook Êã¶Êà™
 * ========================================================================= */

#if defined(__aarch64__)

#define __NR_mprotect 226
#define __NR_prctl    167

static long raw_syscall3(long n, long a, long b, long c) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}

static long raw_syscall5(long n, long a, long b, long c, long d, long e) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4) : "memory");
    return x0;
}

static int raw_mprotect(void* addr, size_t len, int prot) {
    return (int)raw_syscall3(__NR_mprotect, (long)addr, (long)len, (long)prot);
}

static int raw_prctl(int option, unsigned long a2, unsigned long a3,
                     unsigned long a4, unsigned long a5) {
    return (int)raw_syscall5(__NR_prctl, (long)option, (long)a2,
                             (long)a3, (long)a4, (long)a5);
}

#define __NR_read  63
#define __NR_write 64

static long raw_read(int fd, void* buf, size_t count) {
    return raw_syscall3(__NR_read, (long)fd, (long)buf, (long)count);
}

static long raw_write(int fd, const void* buf, size_t count) {
    return raw_syscall3(__NR_write, (long)fd, (long)buf, (long)count);
}

#else
/* Èù?aarch64: ÂõûÈÄÄÂà?libc */
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#define raw_mprotect mprotect
#define raw_prctl    prctl
#define raw_read(fd,buf,n)   read(fd,buf,n)
#define raw_write(fd,buf,n)  write(fd,buf,n)
#endif

/* mmap prot flags */
#ifndef PROT_READ
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4
#endif

/* PLT-free hook_memcpy/hook_memset ‚Ä?‰∏çÁªèËø?libcÔºåÈò≤Ê≠¢Ë¢´ inline hook Êã¶Êà™ */
__attribute__((always_inline))
static inline void* hook_memcpy(void* dst, const void* src, size_t n) {
    volatile uint8_t* d = (volatile uint8_t*)dst;
    const volatile uint8_t* s = (const volatile uint8_t*)src;
    while (n--) *d++ = *s++;
    return dst;
}

__attribute__((always_inline))
static inline void* hook_memset(void* dst, int c, size_t n) {
    volatile uint8_t* d = (volatile uint8_t*)dst;
    while (n--) *d++ = (uint8_t)c;
    return dst;
}

/* wxshadow prctl operations */
#ifndef PR_WXSHADOW_PATCH
#define PR_WXSHADOW_PATCH   0x5758
#endif
#ifndef PR_WXSHADOW_RELEASE
#define PR_WXSHADOW_RELEASE 0x5759
#endif

/* Global engine state */
static HookEngine g_engine = {0};

/* =========================================================================
 * Server pwrite protocol -- target code page read/write via root server
 * ========================================================================= */

#define PATCH_OP_READ  1
#define PATCH_OP_WRITE 2

typedef struct __attribute__((packed)) {
    uint8_t  opcode;
    uint64_t addr;
    uint32_t len;
} PatchReqHeader;

typedef struct __attribute__((packed)) {
    uint8_t  status;
    uint32_t len;
} PatchRespHeader;

static int send_all(int fd, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    while (len > 0) {
        long n = raw_write(fd, p, len);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, void* buf, size_t len) {
    uint8_t* p = (uint8_t*)buf;
    while (len > 0) {
        long n = raw_read(fd, p, len);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/*
 * Read from target code page.
 * Uses server pread if available, otherwise direct hook_memcpy (R-X is readable).
 */
static int target_read(void* addr, void* buf, size_t len) {
    if (g_engine.server_fd >= 0) {
        PatchReqHeader req = { PATCH_OP_READ, (uint64_t)(uintptr_t)addr, (uint32_t)len };
        if (send_all(g_engine.server_fd, &req, sizeof(req)) != 0) goto fallback;
        PatchRespHeader resp;
        if (recv_all(g_engine.server_fd, &resp, sizeof(resp)) != 0) goto fallback;
        if (resp.status != 0 || resp.len != (uint32_t)len) goto fallback;
        if (recv_all(g_engine.server_fd, buf, len) != 0) goto fallback;
        return 0;
    }
fallback:
    /* R-X pages are readable -- direct copy */
    hook_memcpy(buf, addr, len);
    return 0;
}

/*
 * Write to target code page via server pwrite.
 * NO mprotect, NO RWX -- server writes through /proc/<pid>/mem.
 * Caller must flush icache after this returns.
 */
static int target_write(void* addr, const void* buf, size_t len) {
    if (g_engine.server_fd < 0) {
        HOOK_LOGW("target_write: no server fd -- cannot write %p", addr);
        return -1;
    }
    PatchReqHeader req = { PATCH_OP_WRITE, (uint64_t)(uintptr_t)addr, (uint32_t)len };
    if (send_all(g_engine.server_fd, &req, sizeof(req)) != 0) return -1;
    if (send_all(g_engine.server_fd, buf, len) != 0) return -1;
    PatchRespHeader resp;
    if (recv_all(g_engine.server_fd, &resp, sizeof(resp)) != 0) return -1;
    if (resp.status != 0) {
        HOOK_LOGW("target_write: server returned error for %p len=%zu", addr, len);
        return -1;
    }
    HOOK_LOGI("target_write: server pwrite %p len=%zu OK", addr, len);
    return 0;
}



/* Minimum instructions to relocate for our jump sequence.
 * arm64_writer_put_branch_address uses MOVZ/MOVK + BR:
 * - Up to 4 MOV instructions (16 bytes) for 64-bit address
 * - 1 BR instruction (4 bytes)
 * Total: 20 bytes = 5 instructions
 */
#define MIN_HOOK_SIZE 20

/* ARM64 instruction size */
#define INSN_SIZE 4

/* Default allocation sizes */
#define TRAMPOLINE_ALLOC_SIZE 256
#define THUNK_ALLOC_SIZE 512

/* --- Pool write management ---
 * Write strategies (in priority order):
 *   1. Dual-mapping (exec_mem_rw != NULL) ‚Ü?hook_memcpy to RW view, zero RWX ever
 *   2. raw_mprotect toggle: R-X ‚Ü?RWX ‚Ü?write ‚Ü?R-X
 * HookEntry structs live on the heap (malloc), not in the pool.
 */

static int pool_make_writable(void) {
    if (!g_engine.exec_mem) return -1;
    /* No-op: pool_write handles writes via server pwrite internally */
    return 0;
}

static int pool_make_executable(void) {
    if (!g_engine.exec_mem) return -1;
    /* No-op: pool is always R-X; writes go through server pwrite */
    return 0;
}

/* --- Entry free list management (Fix 4: memory reuse) --- */

static HookEntry* alloc_entry(void) {
    HookEntry* entry = NULL;

    if (g_engine.free_list) {
        /* Reuse from free list, preserving pool memory allocations */
        entry = g_engine.free_list;
        g_engine.free_list = entry->next;

        void* saved_trampoline = entry->trampoline;
        size_t saved_trampoline_alloc = entry->trampoline_alloc;
        void* saved_thunk = entry->thunk;
        size_t saved_thunk_alloc = entry->thunk_alloc;

        hook_memset(entry, 0, sizeof(HookEntry));

        entry->trampoline = saved_trampoline;
        entry->trampoline_alloc = saved_trampoline_alloc;
        entry->thunk = saved_thunk;
        entry->thunk_alloc = saved_thunk_alloc;
    } else {
        entry = (HookEntry*)malloc(sizeof(HookEntry));
        if (entry) hook_memset(entry, 0, sizeof(HookEntry));
    }

    return entry;
}

static void free_entry(HookEntry* entry) {
    entry->next = g_engine.free_list;
    g_engine.free_list = entry;
}

/* Flush instruction cache */
void hook_flush_cache(void* start, size_t size) {
#if defined(__aarch64__)
    uintptr_t addr = (uintptr_t)start & ~63UL;
    uintptr_t end  = (uintptr_t)start + size;
    for (; addr < end; addr += 64)
        __asm__ volatile("dc cvau, %0" :: "r"(addr) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    addr = (uintptr_t)start & ~63UL;
    for (; addr < end; addr += 64)
        __asm__ volatile("ic ivau, %0" :: "r"(addr) : "memory");
    __asm__ volatile("dsb ish\nisb" ::: "memory");
#else
    __builtin___clear_cache((char*)start, (char*)start + size);
#endif
}

/*
 * Write data to target address via wxshadow raw_prctl.
 * Automatically handles the case where the patch spans two pages.
 *
 * Returns 0 on success, HOOK_ERROR_WXSHADOW_FAILED on failure.
 */
static int wxshadow_patch(void* addr, const void* buf, size_t len) {
    uintptr_t start = (uintptr_t)addr;
    uintptr_t page_mask = ~(uintptr_t)0xFFF;
    uintptr_t page1 = start & page_mask;
    size_t offset_in_page = start - page1;

    if (offset_in_page + len <= 4096) {
        /* Single page ‚Ä?one raw_prctl call */
        if (raw_prctl(PR_WXSHADOW_PATCH, page1, (unsigned long)buf, len, offset_in_page) != 0) {
            return HOOK_ERROR_WXSHADOW_FAILED;
        }
    } else {
        /* Spans two pages ‚Ä?split into two calls */
        size_t first_len = 4096 - offset_in_page;
        size_t second_len = len - first_len;
        uintptr_t page2 = page1 + 4096;

        if (raw_prctl(PR_WXSHADOW_PATCH, page1, (unsigned long)buf, first_len, offset_in_page) != 0) {
            return HOOK_ERROR_WXSHADOW_FAILED;
        }
        if (raw_prctl(PR_WXSHADOW_PATCH, page2, (unsigned long)((const uint8_t*)buf + first_len), second_len, 0) != 0) {
            return HOOK_ERROR_WXSHADOW_FAILED;
        }
    }
    return 0;
}

/*
 * Release wxshadow pages covering [addr, addr+len).
 * Automatically handles cross-page spans.
 *
 * Returns 0 on success, HOOK_ERROR_WXSHADOW_FAILED on failure.
 */
static int wxshadow_release(void* addr, size_t len) {
    uintptr_t start = (uintptr_t)addr;
    uintptr_t page_mask = ~(uintptr_t)0xFFF;
    uintptr_t page1 = start & page_mask;
    size_t offset_in_page = start - page1;

    if (offset_in_page + len <= 4096) {
        if (raw_prctl(PR_WXSHADOW_RELEASE, page1, len, offset_in_page, 0) != 0) {
            return HOOK_ERROR_WXSHADOW_FAILED;
        }
    } else {
        size_t first_len = 4096 - offset_in_page;
        size_t second_len = len - first_len;
        uintptr_t page2 = page1 + 4096;

        if (raw_prctl(PR_WXSHADOW_RELEASE, page1, first_len, offset_in_page, 0) != 0) {
            return HOOK_ERROR_WXSHADOW_FAILED;
        }
        if (raw_prctl(PR_WXSHADOW_RELEASE, page2, second_len, 0, 0) != 0) {
            return HOOK_ERROR_WXSHADOW_FAILED;
        }
    }
    return 0;
}

/*
 * Write to the hook pool.
 *   1. Dual-mapping: translate R-X addr ‚Ü?RW addr, direct hook_memcpy (no RWX, no syscall)
 *   2. Fallback: direct hook_memcpy (caller made pool RWX via pool_make_writable)
 */
static int pool_write(void* pool_addr, const void* src, size_t len) {
    /* Strategy 1: server pwrite (zero mprotect, zero RWX) */
    if (g_engine.server_fd >= 0) {
        return target_write(pool_addr, src, len);
    }
    /* Strategy 2: mprotect toggle fallback */
    if (raw_mprotect(g_engine.exec_mem, g_engine.exec_mem_size,
                     PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        hook_memcpy(pool_addr, src, len);
        raw_mprotect(g_engine.exec_mem, g_engine.exec_mem_size,
                     PROT_READ | PROT_EXEC);
        return 0;
    }
    return -1;
}

/* Write an absolute jump using arm64_writer (MOVZ/MOVK + BR sequence) */
int hook_write_jump(void* dst, void* target) {
    if (!dst || !target) {
        return HOOK_ERROR_INVALID_PARAM;
    }

    Arm64Writer w;
    arm64_writer_init(&w, dst, (uint64_t)dst, MIN_HOOK_SIZE);
    arm64_writer_put_branch_address(&w, (uint64_t)target);

    /* Check if branch_address exceeded our buffer */
    if (arm64_writer_offset(&w) > MIN_HOOK_SIZE) {
        arm64_writer_clear(&w);
        return HOOK_ERROR_BUFFER_TOO_SMALL;
    }

    /* Fill remaining space with BRK to catch unexpected execution */
    while (arm64_writer_offset(&w) < MIN_HOOK_SIZE && arm64_writer_can_write(&w, 4)) {
        arm64_writer_put_brk_imm(&w, 0xFFFF);
    }

    int bytes_written = (int)arm64_writer_offset(&w);
    arm64_writer_clear(&w);
    return bytes_written;
}

/* Allocate from executable memory pool */
void* hook_alloc(size_t size) {
    if (!g_engine.initialized) return NULL;

    /* Align to 8 bytes */
    size = (size + 7) & ~7;

    if (g_engine.exec_mem_used + size > g_engine.exec_mem_size) {
        return NULL;
    }

    void* ptr = (uint8_t*)g_engine.exec_mem + g_engine.exec_mem_used;
    g_engine.exec_mem_used += size;
    return ptr;
}

/* Relocate instructions from src to dst using arm64_relocator.
 * src_base_addr is the original PC address for PC-relative relocation
 * (may differ from src when reading from a saved copy).
 */
size_t hook_relocate_instructions_ex(void* src, uint64_t src_base_addr, void* dst, size_t min_bytes) {
    Arm64Writer w;
    Arm64Relocator r;
    uint8_t temp[256];

    /* Write to temp buffer; PC = dst (pool address) for correct relocation */
    arm64_writer_init(&w, temp, (uint64_t)dst, 256);
    arm64_relocator_init(&r, src, src_base_addr, &w);

    size_t src_offset = 0;
    while (src_offset < min_bytes) {
        if (arm64_relocator_read_one(&r) == 0) break;
        arm64_relocator_write_one(&r);
        src_offset += INSN_SIZE;
    }

    /* Flush any pending labels */
    arm64_writer_flush(&w);

    size_t written = arm64_writer_offset(&w);

    /* Copy relocated code to pool */
    if (written > 0) {
        pool_write(dst, temp, written);
    }

    arm64_writer_clear(&w);
    arm64_relocator_clear(&r);

    return written;
}

/* Convenience wrapper: src address is also the base address */
size_t hook_relocate_instructions(void* src, void* dst, size_t min_bytes) {
    return hook_relocate_instructions_ex(src, (uint64_t)src, dst, min_bytes);
}

/* Initialize the hook engine */
int hook_engine_init(void* exec_mem, size_t size) {
    if (g_engine.initialized) {
        return 0; /* Already initialized */
    }

    if (!exec_mem || size < 4096) {
        return -1;
    }

    g_engine.exec_mem = exec_mem;
    g_engine.exec_mem_size = size;
    g_engine.exec_mem_used = 0;
    g_engine.hooks = NULL;
    g_engine.free_list = NULL;
    g_engine.exec_mem_page_size = (size_t)4096;
    pthread_mutex_init(&g_engine.lock, NULL);
    g_engine.server_fd = -1;
    g_engine.initialized = 1;

    HOOK_LOGI("pool: R-X %p (%zuKB), writes via server pwrite", exec_mem, size / 1024);

    return 0;
}

/* Find hook entry by target address */
static HookEntry* find_hook(void* target) {
    HookEntry* entry = g_engine.hooks;
    while (entry) {
        if (entry->target == target) return entry;
        entry = entry->next;
    }
    return NULL;
}

/* Install a replacement hook */
void* hook_install(void* target, void* replacement, int stealth) {
    if (!g_engine.initialized || !target || !replacement) {
        return NULL;
    }

    pthread_mutex_lock(&g_engine.lock);

    /* Check if already hooked */
    if (find_hook(target)) {
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    /* Allocate hook entry on heap */
    HookEntry* entry = alloc_entry();
    if (!entry) {
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    entry->target = target;
    entry->replacement = replacement;

    /* Allocate trampoline space in R-X pool */
    if (!entry->trampoline || entry->trampoline_alloc < TRAMPOLINE_ALLOC_SIZE) {
        entry->trampoline = hook_alloc(TRAMPOLINE_ALLOC_SIZE);
        entry->trampoline_alloc = TRAMPOLINE_ALLOC_SIZE;
    }
    if (!entry->trampoline) {
        free_entry(entry);
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    /* Read original bytes via server or direct read (R-X is readable) */
    target_read(target, entry->original_bytes, MIN_HOOK_SIZE);
    entry->original_size = MIN_HOOK_SIZE;

    /* Relocate original instructions to trampoline */
    size_t relocated_size = hook_relocate_instructions_ex(
        entry->original_bytes, (uint64_t)target, entry->trampoline, MIN_HOOK_SIZE);

    /* Write jump-back sequence to pool */
    {
        uint8_t jump_temp[MIN_HOOK_SIZE];
        void* jump_back_target = (uint8_t*)target + MIN_HOOK_SIZE;
        int jump_result = hook_write_jump(jump_temp, jump_back_target);
        if (jump_result < 0) {
            free_entry(entry);
            pthread_mutex_unlock(&g_engine.lock);
            return NULL;
        }
        pool_write((uint8_t*)entry->trampoline + relocated_size, jump_temp, jump_result);
    }

    /* Patch target: write jump to replacement */
    {
        uint8_t jump_buf[MIN_HOOK_SIZE];
        int jump_result = hook_write_jump(jump_buf, replacement);
        if (jump_result < 0) {
            free_entry(entry);
            pthread_mutex_unlock(&g_engine.lock);
            return NULL;
        }
        /* Pad remaining bytes with BRK */
        for (int i = jump_result; i < MIN_HOOK_SIZE; i += 4) {
            *(uint32_t*)(jump_buf + i) = 0xD4200000 | (0xFFFF << 5);
        }

        int patched = 0;

        if (stealth) {
            if (wxshadow_patch(target, jump_buf, MIN_HOOK_SIZE) == 0) {
                entry->stealth = 1;
                patched = 1;
            }
        }

        if (!patched) {
            /* Server pwrite -- zero mprotect, zero RWX */
            if (target_write(target, jump_buf, MIN_HOOK_SIZE) != 0) {
                free_entry(entry);
                pthread_mutex_unlock(&g_engine.lock);
                return NULL;
            }
            entry->stealth = 0;
        }
    }

    /* Flush cache */
    hook_flush_cache(target, MIN_HOOK_SIZE);
    hook_flush_cache(entry->trampoline, TRAMPOLINE_ALLOC_SIZE);

    /* Add to list */
    entry->next = g_engine.hooks;
    g_engine.hooks = entry;

    void* trampoline = entry->trampoline;
    pthread_mutex_unlock(&g_engine.lock);
    return trampoline;
}

/* Generate thunk code for attach hook using arm64_writer */
static void* generate_attach_thunk(HookEntry* entry, HookCallback on_enter,
                                    HookCallback on_leave, void* user_data,
                                    size_t* thunk_size_out) {
    void* thunk_mem;

    /* Reuse thunk memory from free list entry if available and large enough */
    if (entry->thunk && entry->thunk_alloc >= THUNK_ALLOC_SIZE) {
        thunk_mem = entry->thunk;
    } else {
        thunk_mem = hook_alloc(THUNK_ALLOC_SIZE);
        if (!thunk_mem) return NULL;
        entry->thunk = thunk_mem;
        entry->thunk_alloc = THUNK_ALLOC_SIZE;
    }

    uint8_t temp[THUNK_ALLOC_SIZE];
    Arm64Writer w;
    /* Write to temp buffer; PC = thunk_mem for correct addressing */
    arm64_writer_init(&w, temp, (uint64_t)thunk_mem, THUNK_ALLOC_SIZE);

    /* Allocate stack space for HookContext (256 bytes) + saved LR (8 bytes) + alignment */
    /* HookContext: x0-x30 (31*8=248) + sp (8) + pc (8) + nzcv (8) = 272 bytes */
    /* Round up to 16-byte alignment: 288 bytes */
    uint64_t stack_size = 288;
    arm64_writer_put_sub_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, stack_size);

    /* Save x0-x30 to context on stack */
    for (int i = 0; i < 30; i += 2) {
        arm64_writer_put_stp_reg_reg_reg_offset(&w, ARM64_REG_X0 + i, ARM64_REG_X0 + i + 1,
                                                 ARM64_REG_SP, i * 8, ARM64_INDEX_SIGNED_OFFSET);
    }
    /* Save x30 (LR) */
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X30, ARM64_REG_SP, 240);

    /* Save SP before we modified it (add back our allocation) */
    arm64_writer_put_add_reg_reg_imm(&w, ARM64_REG_X16, ARM64_REG_SP, stack_size);
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X16, ARM64_REG_SP, 248); /* sp offset */

    /* Save original PC (target address) to context */
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)entry->target);
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X16, ARM64_REG_SP, 256); /* pc offset */

    /* Call on_enter callback if set */
    if (on_enter) {
        /* Set up arguments: X0 = &HookContext, X1 = user_data */
        arm64_writer_put_mov_reg_reg(&w, ARM64_REG_X0, ARM64_REG_SP);
        arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X1, (uint64_t)user_data);

        /* Call on_enter */
        arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)on_enter);
        arm64_writer_put_blr_reg(&w, ARM64_REG_X16);
    }

    /* Restore x0-x7 (arguments) - they may have been modified by callback */
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X0 + i, ARM64_REG_X0 + i + 1,
                                                 ARM64_REG_SP, i * 8, ARM64_INDEX_SIGNED_OFFSET);
    }

    /* Call original function via trampoline */
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)entry->trampoline);
    arm64_writer_put_blr_reg(&w, ARM64_REG_X16);

    /* Save return value (x0) back to context */
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X0, ARM64_REG_SP, 0);

    /* Call on_leave callback if set */
    if (on_leave) {
        /* Set up arguments: X0 = &HookContext, X1 = user_data */
        arm64_writer_put_mov_reg_reg(&w, ARM64_REG_X0, ARM64_REG_SP);
        arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X1, (uint64_t)user_data);

        /* Call on_leave */
        arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)on_leave);
        arm64_writer_put_blr_reg(&w, ARM64_REG_X16);
    }

    /* Restore x0 (return value, possibly modified by on_leave) */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X0, ARM64_REG_SP, 0);

    /* Restore x30 (LR) */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X30, ARM64_REG_SP, 240);

    /* Deallocate stack */
    arm64_writer_put_add_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, stack_size);

    /* Return */
    arm64_writer_put_ret(&w);

    /* Flush any pending labels */
    arm64_writer_flush(&w);

    *thunk_size_out = arm64_writer_offset(&w);

    /* Copy generated thunk to pool */
    pool_write(thunk_mem, temp, *thunk_size_out);

    arm64_writer_clear(&w);

    return thunk_mem;
}

/* Install a Frida-style hook with callbacks */
int hook_attach(void* target, HookCallback on_enter, HookCallback on_leave, void* user_data, int stealth) {
    if (!g_engine.initialized) {
        return HOOK_ERROR_NOT_INITIALIZED;
    }

    if (!target) {
        return HOOK_ERROR_INVALID_PARAM;
    }

    if (!on_enter && !on_leave) {
        return HOOK_ERROR_INVALID_PARAM; /* At least one callback required */
    }

    pthread_mutex_lock(&g_engine.lock);

    /* Check if already hooked */
    if (find_hook(target)) {
        pthread_mutex_unlock(&g_engine.lock);
        return HOOK_ERROR_ALREADY_HOOKED;
    }

    /* Make pool writable for allocation and code generation */
    if (pool_make_writable() != 0) {
        pthread_mutex_unlock(&g_engine.lock);
        return HOOK_ERROR_MPROTECT_FAILED;
    }

    /* Allocate hook entry (reuse from free list if possible) */
    HookEntry* entry = alloc_entry();
    if (!entry) {
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return HOOK_ERROR_ALLOC_FAILED;
    }

    entry->target = target;
    entry->on_enter = on_enter;
    entry->on_leave = on_leave;
    entry->user_data = user_data;

    /* Read original bytes via server or direct read */
    target_read(target, entry->original_bytes, MIN_HOOK_SIZE);
    entry->original_size = MIN_HOOK_SIZE;

    /* Allocate trampoline (reuse if available and large enough) */
    if (!entry->trampoline || entry->trampoline_alloc < TRAMPOLINE_ALLOC_SIZE) {
        entry->trampoline = hook_alloc(TRAMPOLINE_ALLOC_SIZE);
        entry->trampoline_alloc = TRAMPOLINE_ALLOC_SIZE;
    }
    if (!entry->trampoline) {
        free_entry(entry);
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return HOOK_ERROR_ALLOC_FAILED;
    }

    /* Relocate original instructions to trampoline.
     * Read from saved copy (original_bytes) but use target as PC base address
     * for correct PC-relative relocation.
     */
    size_t relocated_size = hook_relocate_instructions_ex(
        entry->original_bytes, (uint64_t)target, entry->trampoline, MIN_HOOK_SIZE);

    /* Write jump-back sequence to pool */
    {
        uint8_t jump_temp[MIN_HOOK_SIZE];
        void* jump_back_target = (uint8_t*)target + MIN_HOOK_SIZE;
        int jump_result = hook_write_jump(jump_temp, jump_back_target);
        if (jump_result < 0) {
            free_entry(entry);
            pool_make_executable();
            pthread_mutex_unlock(&g_engine.lock);
            return jump_result;
        }
        pool_write((uint8_t*)entry->trampoline + relocated_size, jump_temp, jump_result);
    }

    /* Generate thunk code */
    size_t thunk_size = 0;
    void* thunk_mem = generate_attach_thunk(entry, on_enter, on_leave, user_data, &thunk_size);
    if (!thunk_mem) {
        free_entry(entry);
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return HOOK_ERROR_ALLOC_FAILED;
    }

    /* Tighten pool back to R-X before patching target */
    pool_make_executable();

    /* Patch target: write jump to thunk. */
    {
        uint8_t jump_buf[MIN_HOOK_SIZE];
        int jump_result = hook_write_jump(jump_buf, thunk_mem);
        if (jump_result < 0) {
            free_entry(entry);
            pthread_mutex_unlock(&g_engine.lock);
            return jump_result;
        }
        /* Pad remaining bytes with BRK */
        for (int i = jump_result; i < MIN_HOOK_SIZE; i += 4) {
            *(uint32_t*)(jump_buf + i) = 0xD4200000 | (0xFFFF << 5);
        }

        int patched = 0;

        if (stealth) {
            /* Stealth: wxshadow */
            if (wxshadow_patch(target, jump_buf, MIN_HOOK_SIZE) == 0) {
                entry->stealth = 1;
                patched = 1;
            }
        }

        if (!patched) {
            /* Server pwrite -- zero mprotect, zero RWX */
            if (target_write(target, jump_buf, MIN_HOOK_SIZE) != 0) {
                HOOK_LOGW("hook_attach: server pwrite failed for %p", target);
                free_entry(entry);
                pthread_mutex_unlock(&g_engine.lock);
                return HOOK_ERROR_MPROTECT_FAILED;
            }
            entry->stealth = 0;
            patched = 1;
            HOOK_LOGI("hook_attach: patched %p via server pwrite", target);
        }
    }

    /* Flush caches */
    hook_flush_cache(target, MIN_HOOK_SIZE);
    hook_flush_cache(entry->trampoline, TRAMPOLINE_ALLOC_SIZE);
    hook_flush_cache(thunk_mem, thunk_size);

    /* Add to list */
    entry->next = g_engine.hooks;
    g_engine.hooks = entry;

    pthread_mutex_unlock(&g_engine.lock);
    return HOOK_OK;
}

/* Remove a hook */
int hook_remove(void* target) {
    if (!g_engine.initialized) {
        return HOOK_ERROR_NOT_INITIALIZED;
    }

    if (!target) {
        return HOOK_ERROR_INVALID_PARAM;
    }

    pthread_mutex_lock(&g_engine.lock);

    HookEntry* prev = NULL;
    HookEntry* entry = g_engine.hooks;

    while (entry) {
        if (entry->target == target) {
            if (entry->stealth) {
                /* Stealth hook: release shadow pages to restore original view */
                int rc = wxshadow_release(target, entry->original_size);
                if (rc != 0) {
                    pthread_mutex_unlock(&g_engine.lock);
                    return HOOK_ERROR_WXSHADOW_FAILED;
                }
            } else {
                /* Normal hook: restore original bytes via server pwrite */
                if (target_write(target, entry->original_bytes, entry->original_size) != 0) {
                    pthread_mutex_unlock(&g_engine.lock);
                    return HOOK_ERROR_MPROTECT_FAILED;
                }
                hook_flush_cache(target, entry->original_size);
            }
            hook_flush_cache(target, entry->original_size);

            /* Remove from hook list */
            if (prev) {
                prev->next = entry->next;
            } else {
                g_engine.hooks = entry->next;
            }

            /* Move to free list for reuse instead of discarding */
            free_entry(entry);

            pthread_mutex_unlock(&g_engine.lock);
            return HOOK_OK;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_mutex_unlock(&g_engine.lock);
    return HOOK_ERROR_NOT_FOUND;
}

/* Get trampoline for hooked function */
void* hook_get_trampoline(void* target) {
    pthread_mutex_lock(&g_engine.lock);
    HookEntry* entry = find_hook(target);
    void* result = entry ? entry->trampoline : NULL;
    pthread_mutex_unlock(&g_engine.lock);
    return result;
}

/* Cleanup all hooks */
void hook_engine_cleanup(void) {
    if (!g_engine.initialized) return;

    pthread_mutex_lock(&g_engine.lock);

    /* Restore all hooks and free heap-allocated entries */
    HookEntry* entry = g_engine.hooks;
    while (entry) {
        if (entry->stealth) {
            wxshadow_release(entry->target, entry->original_size);
        } else {
            target_write(entry->target, entry->original_bytes, entry->original_size);
        }
        hook_flush_cache(entry->target, entry->original_size);
        HookEntry* next = entry->next;
        free(entry);
        entry = next;
    }

    /* Free entries in free list */
    HookEntry* fentry = g_engine.free_list;
    while (fentry) {
        HookEntry* next = fentry->next;
        free(fentry);
        fentry = next;
    }

    /* Reset state */
    g_engine.hooks = NULL;
    g_engine.free_list = NULL;
    g_engine.exec_mem_used = 0;
    g_engine.initialized = 0;

    pthread_mutex_unlock(&g_engine.lock);
    pthread_mutex_destroy(&g_engine.lock);
}
/* Set patcher server socket fd */
void hook_engine_set_server(int fd) {
    g_engine.server_fd = fd;
    if (fd >= 0) {
        HOOK_LOGI("server fd set to %d -- target writes via pwrite", fd);
    }
}
