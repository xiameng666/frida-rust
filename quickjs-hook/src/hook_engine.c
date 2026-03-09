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
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

/* wxshadow prctl operations - shadow page patching */
#ifndef PR_WXSHADOW_PATCH
#define PR_WXSHADOW_PATCH   0x5758    /* prctl(PR_WXSHADOW_PATCH, page_addr, buf, len) */
#endif
#ifndef PR_WXSHADOW_RELEASE
#define PR_WXSHADOW_RELEASE 0x5759    /* prctl(PR_WXSHADOW_RELEASE, page_addr, len) */
#endif

/* Global engine state */
static HookEngine g_engine = {0};

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

/* --- Pool permission management ---
 * Pool 始终保持 R-X 权限，所有写入通过 /proc/self/mem 完成。
 * /proc/self/maps 中不会出现 rwxp 匿名映射。
 * HookEntry 结构体在堆上分配(malloc)，不占用 R-X pool。
 * pool_make_writable / pool_make_executable 保留为 no-op 以保持调用结构。
 */

static int pool_make_writable(void) {
    /* Pool 始终 R-X，写入通过 /proc/self/mem */
    return 0;
}

static int pool_make_executable(void) {
    /* Pool 始终 R-X，无需切换 */
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

        memset(entry, 0, sizeof(HookEntry));

        entry->trampoline = saved_trampoline;
        entry->trampoline_alloc = saved_trampoline_alloc;
        entry->thunk = saved_thunk;
        entry->thunk_alloc = saved_thunk_alloc;
    } else {
        entry = (HookEntry*)malloc(sizeof(HookEntry));
        if (entry) memset(entry, 0, sizeof(HookEntry));
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
 * Write data to target address via wxshadow prctl.
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
        /* Single page — one prctl call */
        if (prctl(PR_WXSHADOW_PATCH, page1, buf, len, offset_in_page) != 0) {
            return HOOK_ERROR_WXSHADOW_FAILED;
        }
    } else {
        /* Spans two pages — split into two calls */
        size_t first_len = 4096 - offset_in_page;
        size_t second_len = len - first_len;
        uintptr_t page2 = page1 + 4096;

        if (prctl(PR_WXSHADOW_PATCH, page1, buf, first_len, offset_in_page) != 0) {
            return HOOK_ERROR_WXSHADOW_FAILED;
        }
        if (prctl(PR_WXSHADOW_PATCH, page2, (const uint8_t*)buf + first_len, second_len, 0) != 0) {
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
        if (prctl(PR_WXSHADOW_RELEASE, page1, len, offset_in_page, 0) != 0) {
            return HOOK_ERROR_WXSHADOW_FAILED;
        }
    } else {
        size_t first_len = 4096 - offset_in_page;
        size_t second_len = len - first_len;
        uintptr_t page2 = page1 + 4096;

        if (prctl(PR_WXSHADOW_RELEASE, page1, first_len, offset_in_page, 0) != 0) {
            return HOOK_ERROR_WXSHADOW_FAILED;
        }
        if (prctl(PR_WXSHADOW_RELEASE, page2, second_len, 0, 0) != 0) {
            return HOOK_ERROR_WXSHADOW_FAILED;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * /proc/self/mem helpers — bypass SELinux mprotect restrictions
 * ---------------------------------------------------------------------------*/

/*
 * Read `len` bytes from virtual address `addr` via /proc/self/mem.
 * Returns 0 on success, -1 on failure.
 */
static int proc_mem_read(void* dst, const void* addr, size_t len) {
    int fd = open("/proc/self/mem", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, dst, len, (off_t)(uintptr_t)addr);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

/*
 * Write `len` bytes to virtual address `addr` via /proc/self/mem.
 * Returns 0 on success, -1 on failure.
 */
static int proc_mem_write(void* addr, const void* src, size_t len) {
    int fd = open("/proc/self/mem", O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = pwrite(fd, src, len, (off_t)(uintptr_t)addr);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
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

    /* Copy relocated code to R-X pool via /proc/self/mem */
    if (written > 0) {
        proc_mem_write(dst, temp, written);
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
    g_engine.exec_mem_page_size = (size_t)sysconf(_SC_PAGESIZE);
    pthread_mutex_init(&g_engine.lock, NULL);
    g_engine.initialized = 1;

    /* Pool is R-X; all writes go through /proc/self/mem */
    pool_make_executable();

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

    /* Read original bytes via /proc/self/mem (works on execute-only pages) */
    if (proc_mem_read(entry->original_bytes, target, MIN_HOOK_SIZE) != 0) {
        uintptr_t target_page = (uintptr_t)target & ~0xFFF;
        if (mprotect((void*)target_page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            free_entry(entry);
            pthread_mutex_unlock(&g_engine.lock);
            return NULL;
        }
        memcpy(entry->original_bytes, target, MIN_HOOK_SIZE);
    }
    entry->original_size = MIN_HOOK_SIZE;

    /* Relocate original instructions to trampoline (writes to pool via proc_mem_write) */
    size_t relocated_size = hook_relocate_instructions_ex(
        entry->original_bytes, (uint64_t)target, entry->trampoline, MIN_HOOK_SIZE);

    /* Write jump back → temp buffer then proc_mem_write to pool */
    {
        uint8_t jump_temp[MIN_HOOK_SIZE];
        void* jump_back_target = (uint8_t*)target + MIN_HOOK_SIZE;
        int jump_result = hook_write_jump(jump_temp, jump_back_target);
        if (jump_result < 0) {
            free_entry(entry);
            pthread_mutex_unlock(&g_engine.lock);
            return NULL;
        }
        proc_mem_write((uint8_t*)entry->trampoline + relocated_size, jump_temp, jump_result);
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
            if (proc_mem_write(target, jump_buf, MIN_HOOK_SIZE) == 0) {
                entry->stealth = 0;
                patched = 1;
            }
        }

        if (!patched) {
            /* Last resort: mprotect + direct write */
            uintptr_t target_page = (uintptr_t)target & ~0xFFF;
            if (mprotect((void*)target_page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                free_entry(entry);
                pthread_mutex_unlock(&g_engine.lock);
                return NULL;
            }
            memcpy(target, jump_buf, MIN_HOOK_SIZE);
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

    /* Copy generated thunk to R-X pool via /proc/self/mem */
    proc_mem_write(thunk_mem, temp, *thunk_size_out);

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

    /*
     * Read original bytes via /proc/self/mem (works even on execute-only pages).
     * Falls back to direct memcpy if /proc/self/mem fails.
     */
    if (proc_mem_read(entry->original_bytes, target, MIN_HOOK_SIZE) != 0) {
        /* Fallback: try mprotect + direct read */
        uintptr_t target_page = (uintptr_t)target & ~0xFFF;
        if (mprotect((void*)target_page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            free_entry(entry);
            pool_make_executable();
            pthread_mutex_unlock(&g_engine.lock);
            return HOOK_ERROR_MPROTECT_FAILED;
        }
        memcpy(entry->original_bytes, target, MIN_HOOK_SIZE);
    }
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

    /* Write jump back → temp buffer then proc_mem_write to pool */
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
        proc_mem_write((uint8_t*)entry->trampoline + relocated_size, jump_temp, jump_result);
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

    /* Patch target: write jump to thunk.
     * Try /proc/self/mem first (no mprotect needed), then mprotect fallback,
     * then wxshadow for stealth mode.
     */
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
            /* Try /proc/self/mem write (bypasses SELinux mprotect block) */
            if (proc_mem_write(target, jump_buf, MIN_HOOK_SIZE) == 0) {
                entry->stealth = 0;
                patched = 1;
            }
        }

        if (!patched) {
            /* Last resort: mprotect + direct write */
            uintptr_t target_page = (uintptr_t)target & ~0xFFF;
            if (mprotect((void*)target_page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                free_entry(entry);
                pthread_mutex_unlock(&g_engine.lock);
                return HOOK_ERROR_MPROTECT_FAILED;
            }
            memcpy(target, jump_buf, MIN_HOOK_SIZE);
            entry->stealth = 0;
            patched = 1;
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
                /* Normal hook: restore original bytes via /proc/self/mem or mprotect */
                if (proc_mem_write(target, entry->original_bytes, entry->original_size) != 0) {
                    uintptr_t page_start = (uintptr_t)target & ~0xFFF;
                    if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                        pthread_mutex_unlock(&g_engine.lock);
                        return HOOK_ERROR_MPROTECT_FAILED;
                    }
                    memcpy(target, entry->original_bytes, entry->original_size);
                }
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
            if (proc_mem_write(entry->target, entry->original_bytes, entry->original_size) != 0) {
                uintptr_t page_start = (uintptr_t)entry->target & ~0xFFF;
                mprotect((void*)page_start, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC);
                memcpy(entry->target, entry->original_bytes, entry->original_size);
            }
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
