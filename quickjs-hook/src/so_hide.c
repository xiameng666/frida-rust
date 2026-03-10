/*
 * so_hide.c - Hide injected SO from linker data structures
 *
 * Implementation:
 *   1. Parse linker64 ELF .symtab to resolve solist / _r_debug addresses
 *   2. Traverse soinfo linked list, unlink target SO via server pwrite
 *   3. Traverse _r_debug->r_map (link_map chain), unlink target SO
 *   4. Erase ELF header at SO base address via server pwrite
 */

#include "so_hide.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#ifdef __ANDROID__
#include <android/log.h>
#define HIDE_TAG "XiaM-hide"
#define HIDE_LOGI(...) __android_log_print(ANDROID_LOG_INFO,  HIDE_TAG, __VA_ARGS__)
#define HIDE_LOGW(...) __android_log_print(ANDROID_LOG_WARN,  HIDE_TAG, __VA_ARGS__)
#define HIDE_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, HIDE_TAG, __VA_ARGS__)
#else
#define HIDE_LOGI(...) fprintf(stderr, __VA_ARGS__)
#define HIDE_LOGW(...) fprintf(stderr, __VA_ARGS__)
#define HIDE_LOGE(...) fprintf(stderr, __VA_ARGS__)
#endif

/* ---------- patcher server protocol (same as hook_engine.c) ---------- */

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

/* soinfo layout constants (LP64, Android 10-14) */
#define SOINFO_OFF_BASE  16
#define SOINFO_OFF_SIZE  24
#define SOINFO_OFF_NEXT  40

/* ---------- module state ---------- */

static int g_server_fd = -1;
static uintptr_t g_solist_addr   = 0;  /* address of solist pointer variable */
static uintptr_t g_r_debug_addr  = 0;  /* address of _r_debug struct */
static int g_initialized = 0;

/* ---------- low-level I/O helpers ---------- */

static inline long raw_write(int fd, const void* buf, size_t len) {
    return syscall(SYS_write, fd, buf, len);
}

static inline long raw_read(int fd, void* buf, size_t len) {
    return syscall(SYS_read, fd, buf, len);
}

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

/* Read from target process memory via server pread */
static int server_pread(void* buf, uintptr_t addr, size_t len) {
    if (g_server_fd < 0) return -1;
    PatchReqHeader req = { PATCH_OP_READ, (uint64_t)addr, (uint32_t)len };
    if (send_all(g_server_fd, &req, sizeof(req)) != 0) return -1;
    PatchRespHeader resp;
    if (recv_all(g_server_fd, &resp, sizeof(resp)) != 0) return -1;
    if (resp.status != 0 || resp.len != (uint32_t)len) return -1;
    return recv_all(g_server_fd, buf, len);
}

/* Write to target process memory via server pwrite */
static int server_pwrite(uintptr_t addr, const void* buf, size_t len) {
    if (g_server_fd < 0) return -1;
    PatchReqHeader req = { PATCH_OP_WRITE, (uint64_t)addr, (uint32_t)len };
    if (send_all(g_server_fd, &req, sizeof(req)) != 0) return -1;
    if (send_all(g_server_fd, buf, len) != 0) return -1;
    PatchRespHeader resp;
    if (recv_all(g_server_fd, &resp, sizeof(resp)) != 0) return -1;
    return resp.status == 0 ? 0 : -1;
}

/* ---------- /proc/self/maps parser ---------- */

typedef struct {
    uintptr_t base;
    char path[256];
} LinkerMapInfo;

static int find_linker_in_maps(LinkerMapInfo* out) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return -1;

    char line[512];
    int found = 0;

    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start, end;
        char perms[5];
        unsigned long offset;
        char dev[32];
        unsigned long inode;
        char path[256] = "";

        if (sscanf(line, "%lx-%lx %4s %lx %31s %lu %255[^\n]",
                   &start, &end, perms, &offset, dev, &inode, path) >= 6) {
            /* Match linker64 by path — first mapping with offset 0 is the base */
            if (strstr(path, "linker64") && offset == 0 && !found) {
                out->base = start;
                /* Trim leading spaces */
                const char* p = path;
                while (*p == ' ') p++;
                strncpy(out->path, p, sizeof(out->path) - 1);
                out->path[sizeof(out->path) - 1] = '\0';
                found = 1;
                /* Don't break — keep reading to consume the file */
            }
        }
    }

    fclose(fp);
    return found ? 0 : -1;
}

/* ---------- ELF parser for linker64 .symtab ---------- */

typedef struct {
    const char*   name;
    uintptr_t     runtime_addr;
} ResolvedSymbol;

/*
 * Parse linker64 ELF file to find symbol addresses.
 * Resolves symbols from .symtab section (includes static locals).
 *
 * @param file_path   Path to linker64 on disk
 * @param base_addr   Runtime base address of linker64
 * @param syms        Array of ResolvedSymbol (name filled, addr to be filled)
 * @param sym_count   Number of symbols to resolve
 * @return            Number of symbols successfully resolved
 */
static int resolve_linker_symbols(const char* file_path, uintptr_t base_addr,
                                  ResolvedSymbol* syms, int sym_count) {
    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        HIDE_LOGE("cannot open %s", file_path);
        return 0;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return 0;
    }

    void* map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return 0;

    const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)map;

    /* Validate ELF */
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        munmap(map, st.st_size);
        return 0;
    }

    /* Compute load bias from first PT_LOAD segment */
    uintptr_t load_bias = 0;
    const Elf64_Phdr* phdrs = (const Elf64_Phdr*)((uint8_t*)map + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            load_bias = base_addr - phdrs[i].p_vaddr;
            break;
        }
    }

    /* Find .symtab and its associated .strtab via section headers */
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0) {
        HIDE_LOGW("no section headers in %s", file_path);
        munmap(map, st.st_size);
        return 0;
    }

    const Elf64_Shdr* shdrs = (const Elf64_Shdr*)((uint8_t*)map + ehdr->e_shoff);
    const Elf64_Shdr* shstrtab_hdr = &shdrs[ehdr->e_shstrndx];
    const char* shstrtab = (const char*)((uint8_t*)map + shstrtab_hdr->sh_offset);

    const Elf64_Shdr* symtab_hdr = NULL;
    const Elf64_Shdr* strtab_hdr = NULL;
    const Elf64_Shdr* dynsym_hdr = NULL;
    const Elf64_Shdr* dynstr_hdr = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char* sec_name = shstrtab + shdrs[i].sh_name;
        if (shdrs[i].sh_type == SHT_SYMTAB && strcmp(sec_name, ".symtab") == 0) {
            symtab_hdr = &shdrs[i];
            if (shdrs[i].sh_link < ehdr->e_shnum)
                strtab_hdr = &shdrs[shdrs[i].sh_link];
        }
        if (shdrs[i].sh_type == SHT_DYNSYM && strcmp(sec_name, ".dynsym") == 0) {
            dynsym_hdr = &shdrs[i];
            if (shdrs[i].sh_link < ehdr->e_shnum)
                dynstr_hdr = &shdrs[shdrs[i].sh_link];
        }
    }

    int resolved = 0;

    /* Search .symtab first (has static locals) */
    if (symtab_hdr && strtab_hdr) {
        const Elf64_Sym* sym_arr = (const Elf64_Sym*)((uint8_t*)map + symtab_hdr->sh_offset);
        const char* str_tab = (const char*)((uint8_t*)map + strtab_hdr->sh_offset);
        size_t sym_num = symtab_hdr->sh_size / sizeof(Elf64_Sym);

        for (size_t i = 0; i < sym_num && resolved < sym_count; i++) {
            if (sym_arr[i].st_name == 0 || sym_arr[i].st_value == 0) continue;
            const char* sname = str_tab + sym_arr[i].st_name;
            for (int j = 0; j < sym_count; j++) {
                if (syms[j].runtime_addr != 0) continue;  /* already resolved */
                if (strcmp(sname, syms[j].name) == 0) {
                    syms[j].runtime_addr = load_bias + sym_arr[i].st_value;
                    resolved++;
                    HIDE_LOGI("resolved %s -> %p", sname, (void*)syms[j].runtime_addr);
                    break;
                }
            }
        }
    }

    /* Fallback: search .dynsym for any unresolved */
    if (resolved < sym_count && dynsym_hdr && dynstr_hdr) {
        const Elf64_Sym* sym_arr = (const Elf64_Sym*)((uint8_t*)map + dynsym_hdr->sh_offset);
        const char* str_tab = (const char*)((uint8_t*)map + dynstr_hdr->sh_offset);
        size_t sym_num = dynsym_hdr->sh_size / sizeof(Elf64_Sym);

        for (size_t i = 0; i < sym_num && resolved < sym_count; i++) {
            if (sym_arr[i].st_name == 0 || sym_arr[i].st_value == 0) continue;
            const char* sname = str_tab + sym_arr[i].st_name;
            for (int j = 0; j < sym_count; j++) {
                if (syms[j].runtime_addr != 0) continue;
                if (strcmp(sname, syms[j].name) == 0) {
                    syms[j].runtime_addr = load_bias + sym_arr[i].st_value;
                    resolved++;
                    HIDE_LOGI("resolved (dynsym) %s -> %p", sname, (void*)syms[j].runtime_addr);
                    break;
                }
            }
        }
    }

    munmap(map, st.st_size);
    return resolved;
}

/* ---------- dl_iterate_phdr helpers ---------- */

typedef struct {
    const char* pattern;
    uintptr_t   base;
    char        name[256];
    int         found;
} FindSoCtx;

static int find_so_callback(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    FindSoCtx* ctx = (FindSoCtx*)data;
    if (info->dlpi_name && strstr(info->dlpi_name, ctx->pattern)) {
        ctx->base = info->dlpi_addr;
        strncpy(ctx->name, info->dlpi_name, sizeof(ctx->name) - 1);
        ctx->name[sizeof(ctx->name) - 1] = '\0';
        ctx->found = 1;
        return 1;
    }
    return 0;
}

static int enum_so_callback(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    (void)data;
    HIDE_LOGI("  [phdr] base=%p name=%s",
              (void*)info->dlpi_addr,
              info->dlpi_name ? info->dlpi_name : "<null>");
    return 0;
}

/* ---------- soinfo linked list removal ---------- */

static int remove_from_solist(uintptr_t target_base) {
    if (g_solist_addr == 0) {
        HIDE_LOGW("solist addr not resolved, skip soinfo removal");
        return 0;
    }

    /* Read the solist head pointer */
    uintptr_t current = 0;
    if (server_pread(&current, g_solist_addr, sizeof(current)) != 0) {
        /* Try direct read as fallback */
        current = *(uintptr_t*)g_solist_addr;
    }
    if (current == 0) {
        HIDE_LOGW("solist is NULL");
        return 0;
    }

    uintptr_t prev_next_addr = g_solist_addr;  /* address of the pointer to patch */
    int found = 0;

    while (current != 0) {
        /* Read base field at offset 16 */
        uintptr_t so_base = 0;
        uintptr_t base_field_addr = current + SOINFO_OFF_BASE;
        if (server_pread(&so_base, base_field_addr, sizeof(so_base)) != 0) {
            so_base = *(uintptr_t*)base_field_addr;
        }

        if (so_base == target_base) {
            /* Read current->next */
            uintptr_t next = 0;
            uintptr_t next_field_addr = current + SOINFO_OFF_NEXT;
            if (server_pread(&next, next_field_addr, sizeof(next)) != 0) {
                next = *(uintptr_t*)next_field_addr;
            }

            /* Patch prev->next = current->next */
            if (server_pwrite(prev_next_addr, &next, sizeof(next)) == 0) {
                HIDE_LOGI("soinfo unlinked: node=%p base=%p", (void*)current, (void*)target_base);
                found = 1;
            } else {
                HIDE_LOGE("failed to pwrite prev->next at %p", (void*)prev_next_addr);
            }
            break;
        }

        /* Advance: prev_next_addr = &current->next */
        prev_next_addr = current + SOINFO_OFF_NEXT;

        /* Read next pointer */
        uintptr_t next = 0;
        if (server_pread(&next, prev_next_addr, sizeof(next)) != 0) {
            next = *(uintptr_t*)prev_next_addr;
        }
        current = next;
    }

    return found;
}

/* ---------- link_map chain removal ---------- */

static int remove_from_link_map(const char* so_name) {
    if (g_r_debug_addr == 0) {
        HIDE_LOGW("_r_debug addr not resolved, skip link_map removal");
        return 0;
    }

    /* r_debug layout: { int r_version; struct link_map* r_map; ... }
     * On LP64: r_version at offset 0 (int, 4 bytes + 4 padding), r_map at offset 8 */
    uintptr_t r_map_field_addr = g_r_debug_addr + 8;
    uintptr_t map_head = 0;

    if (server_pread(&map_head, r_map_field_addr, sizeof(map_head)) != 0) {
        map_head = *(uintptr_t*)r_map_field_addr;
    }
    if (map_head == 0) {
        HIDE_LOGW("r_map is NULL");
        return 0;
    }

    /*
     * struct link_map {
     *   ElfW(Addr) l_addr;            // 0
     *   char*      l_name;            // 8
     *   ElfW(Dyn)* l_ld;             // 16
     *   struct link_map* l_next;      // 24
     *   struct link_map* l_prev;      // 32
     * };
     */
    #define LM_OFF_NAME 8
    #define LM_OFF_NEXT 24
    #define LM_OFF_PREV 32

    uintptr_t prev = 0;
    uintptr_t current = map_head;
    int found = 0;

    while (current != 0) {
        /* Read l_name pointer */
        uintptr_t name_ptr = 0;
        if (server_pread(&name_ptr, current + LM_OFF_NAME, sizeof(name_ptr)) != 0) {
            name_ptr = *(uintptr_t*)(current + LM_OFF_NAME);
        }

        /* Read the name string (directly — l_name points to readable memory) */
        char name_buf[256] = "";
        if (name_ptr != 0) {
            /* Direct read; l_name strings are in readable memory */
            strncpy(name_buf, (const char*)name_ptr, sizeof(name_buf) - 1);
        }

        if (strstr(name_buf, so_name)) {
            /* Read current->l_next and current->l_prev */
            uintptr_t next = 0, prev_ptr = 0;
            if (server_pread(&next, current + LM_OFF_NEXT, sizeof(next)) != 0) {
                next = *(uintptr_t*)(current + LM_OFF_NEXT);
            }
            if (server_pread(&prev_ptr, current + LM_OFF_PREV, sizeof(prev_ptr)) != 0) {
                prev_ptr = *(uintptr_t*)(current + LM_OFF_PREV);
            }

            /* Patch prev->l_next = current->l_next */
            if (prev != 0) {
                server_pwrite(prev + LM_OFF_NEXT, &next, sizeof(next));
            } else {
                /* current is head — update r_debug->r_map */
                server_pwrite(r_map_field_addr, &next, sizeof(next));
            }

            /* Patch next->l_prev = current->l_prev */
            if (next != 0) {
                uintptr_t prev_to_write = prev_ptr;
                server_pwrite(next + LM_OFF_PREV, &prev_to_write, sizeof(prev_to_write));
            }

            HIDE_LOGI("link_map unlinked: node=%p name=%s", (void*)current, name_buf);
            found = 1;
            break;
        }

        prev = current;
        /* Read current->l_next */
        if (server_pread(&current, current + LM_OFF_NEXT, sizeof(current)) != 0) {
            current = *(uintptr_t*)(current + LM_OFF_NEXT);
            /* Avoid infinite loop on read failure */
            if (current == prev) break;
        }
    }

    return found;
}

/* ---------- ELF header erasure ---------- */

static int erase_elf_header(uintptr_t base) {
    if (base == 0) return 0;

    uint8_t zeros[64];
    memset(zeros, 0, sizeof(zeros));

    if (server_pwrite(base, zeros, sizeof(zeros)) == 0) {
        HIDE_LOGI("ELF header erased at %p", (void*)base);
        return 1;
    } else {
        HIDE_LOGE("failed to erase ELF header at %p", (void*)base);
        return 0;
    }
}

/* ---------- public API ---------- */

int so_hide_init(int server_fd) {
    g_server_fd = server_fd;

    /* Find linker64 base and path from /proc/self/maps */
    LinkerMapInfo lmi = {0};
    if (find_linker_in_maps(&lmi) != 0) {
        HIDE_LOGE("linker64 not found in /proc/self/maps");
        return -1;
    }
    HIDE_LOGI("linker64: base=%p path=%s", (void*)lmi.base, lmi.path);

    /* Resolve symbols from linker64 ELF */
    ResolvedSymbol syms[] = {
        { "__dl__ZL6solist",  0 },
        { "__dl__r_debug",    0 },
    };
    int n = resolve_linker_symbols(lmi.path, lmi.base, syms, 2);

    if (syms[0].runtime_addr) {
        g_solist_addr = syms[0].runtime_addr;
        HIDE_LOGI("solist @ %p", (void*)g_solist_addr);
    }
    if (syms[1].runtime_addr) {
        g_r_debug_addr = syms[1].runtime_addr;
        HIDE_LOGI("_r_debug @ %p", (void*)g_r_debug_addr);
    }

    if (n == 0) {
        HIDE_LOGW("no linker symbols resolved (symtab stripped?)");
        return -2;
    }

    g_initialized = 1;
    HIDE_LOGI("so_hide_init OK (%d/%d symbols resolved)", n, 2);
    return 0;
}

int so_hide_execute(const char* so_name) {
    if (!g_initialized) {
        HIDE_LOGE("not initialized");
        return -1;
    }
    if (!so_name || !*so_name) {
        return -2;
    }

    int result = 0;

    /* Step 1: Find target SO via dl_iterate_phdr */
    FindSoCtx ctx = { .pattern = so_name, .base = 0, .found = 0 };
    dl_iterate_phdr(find_so_callback, &ctx);

    if (!ctx.found) {
        HIDE_LOGW("SO matching '%s' not found via dl_iterate_phdr", so_name);
        /* Try to continue with link_map removal anyway */
    } else {
        HIDE_LOGI("target SO: base=%p name=%s", (void*)ctx.base, ctx.name);
    }

    /* Step 2: Remove from soinfo linked list */
    if (ctx.found && remove_from_solist(ctx.base)) {
        result |= SO_HIDE_SOLIST;
    }

    /* Step 3: Remove from link_map chain */
    if (remove_from_link_map(so_name)) {
        result |= SO_HIDE_LINKMAP;
    }

    /* Step 4: Erase ELF header */
    if (ctx.found && erase_elf_header(ctx.base)) {
        result |= SO_HIDE_ELFHDR;
    }

    HIDE_LOGI("so_hide_execute('%s') result=0x%x [solist=%d linkmap=%d elfhdr=%d]",
              so_name, result,
              !!(result & SO_HIDE_SOLIST),
              !!(result & SO_HIDE_LINKMAP),
              !!(result & SO_HIDE_ELFHDR));

    return result;
}

void so_hide_test(const char* so_name) {
    HIDE_LOGI("=== so_hide_test('%s') BEGIN ===", so_name);

    /* Before: enumerate all loaded SOs */
    HIDE_LOGI("--- BEFORE hiding ---");
    dl_iterate_phdr(enum_so_callback, NULL);

    /* Execute hiding */
    int rc = so_hide_execute(so_name);
    HIDE_LOGI("so_hide_execute returned 0x%x", rc);

    /* After: enumerate again */
    HIDE_LOGI("--- AFTER hiding ---");
    dl_iterate_phdr(enum_so_callback, NULL);

    HIDE_LOGI("=== so_hide_test END ===");
}
