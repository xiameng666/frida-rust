/*
 * test_pwrite.c — 测试 pwrite /proc/pid/mem
 *
 * 三种模式:
 *   ./test_pwrite self       → 自己 pwrite /proc/self/mem (测试 app 域)
 *   ./test_pwrite target     → 作为目标进程，分配 R-X 页，等待被 patch
 *   ./test_pwrite patch <pid> <addr> → root server 模式，pwrite 目标进程的 /proc/<pid>/mem
 *
 * 编译: just test-pwrite
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

/* ---- aarch64 raw syscall wrappers ---- */

#define __NR_openat   56
#define __NR_close    57
#define __NR_pread64  67
#define __NR_pwrite64 68
#define __NR_mprotect 226
#define __NR_mmap     222
#define __NR_munmap   215

#define AT_FDCWD      -100
#define O_RDONLY      0
#define O_WRONLY      1
#define O_RDWR        2

#ifndef PROT_READ
#define PROT_READ     0x1
#define PROT_WRITE    0x2
#define PROT_EXEC     0x4
#endif

#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20
#define MAP_SHARED    0x01

static long raw_syscall2(long n, long a, long b) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1) : "memory");
    return x0;
}

static long raw_syscall3(long n, long a, long b, long c) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}

static long raw_syscall4(long n, long a, long b, long c, long d) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return x0;
}

static long raw_syscall6(long n, long a, long b, long c, long d, long e, long f) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
    return x0;
}

#define raw_openat(dirfd, path, flags)    raw_syscall3(__NR_openat, (long)(dirfd), (long)(path), (long)(flags))
#define raw_close(fd)                     raw_syscall2(__NR_close, (long)(fd), 0)
#define raw_pread(fd, buf, count, off)    raw_syscall4(__NR_pread64, (long)(fd), (long)(buf), (long)(count), (long)(off))
#define raw_pwrite(fd, buf, count, off)   raw_syscall4(__NR_pwrite64, (long)(fd), (long)(buf), (long)(count), (long)(off))
#define raw_mprotect(addr, len, prot)     raw_syscall3(__NR_mprotect, (long)(addr), (long)(len), (long)(prot))
#define raw_mmap(addr, len, prot, flags, fd, off) \
    raw_syscall6(__NR_mmap, (long)(addr), (long)(len), (long)(prot), (long)(flags), (long)(fd), (long)(off))
#define raw_munmap(addr, len)             raw_syscall2(__NR_munmap, (long)(addr), (long)(len))

/* ---- Mode 1: self pwrite /proc/self/mem ---- */
static int test_self(void) {
    printf("=== self pwrite test ===\n");
    printf("pid=%d  selinux: ", (int)getpid());
    fflush(stdout);
    /* print SELinux context */
    FILE* ctx = fopen("/proc/self/attr/current", "r");
    if (ctx) {
        char buf[256] = {0};
        fread(buf, 1, sizeof(buf)-1, ctx);
        fclose(ctx);
        printf("%s\n", buf);
    } else {
        printf("(unknown)\n");
    }

    /* Allocate R-X page */
    void* code = (void*)raw_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)code < 0) {
        printf("mmap FAILED (%ld)\n", (long)code);
        return 1;
    }
    memset(code, 0x00, 4096);
    raw_mprotect(code, 4096, PROT_READ | PROT_EXEC);
    printf("code page at %p (R-X)\n", code);

    /* Try pwrite */
    long fd = raw_openat(AT_FDCWD, "/proc/self/mem", O_RDWR);
    printf("raw openat(/proc/self/mem, O_RDWR) = %ld %s\n", fd, fd >= 0 ? "OK" : "FAILED");

    if (fd < 0) {
        printf("RESULT: pwrite NOT available (openat errno=%ld)\n", -fd);
        raw_munmap(code, 4096);
        return 1;
    }

    uint8_t patch[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    long n = raw_pwrite(fd, patch, 4, (long)code);
    printf("raw pwrite to R-X page: ret=%ld %s\n", n, n == 4 ? "OK" : "FAILED");

    if (n == 4) {
        /* Read back via pread */
        uint8_t buf[4] = {0};
        long r = raw_pread(fd, buf, 4, (long)code);
        printf("readback: %02x%02x%02x%02x %s\n", buf[0], buf[1], buf[2], buf[3],
               (r == 4 && buf[0] == 0xDE) ? "OK" : "FAILED");
        printf("RESULT: pwrite WORKS — can write R-X without mprotect!\n");
    } else {
        printf("RESULT: pwrite FAILED (errno=%ld) — need server approach\n", -n);
    }

    raw_close(fd);
    raw_munmap(code, 4096);
    return n == 4 ? 0 : 1;
}

/* ---- Mode 2: target — allocate R-X page, wait for server to patch ---- */
static volatile int g_patched = 0;
static void sig_handler(int sig) { (void)sig; g_patched = 1; }

static int test_target(void) {
    printf("=== target mode ===\n");
    printf("pid=%d  selinux: ", (int)getpid());
    fflush(stdout);
    FILE* ctx = fopen("/proc/self/attr/current", "r");
    if (ctx) {
        char buf[256] = {0};
        fread(buf, 1, sizeof(buf)-1, ctx);
        fclose(ctx);
        printf("%s\n", buf);
    } else {
        printf("(unknown)\n");
    }

    /* Allocate R-X page */
    void* code = (void*)raw_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)code < 0) {
        printf("mmap FAILED\n");
        return 1;
    }
    memset(code, 0x00, 4096);
    raw_mprotect(code, 4096, PROT_READ | PROT_EXEC);

    /* Print info for server */
    printf("ADDR=0x%lx\n", (unsigned long)code);
    printf("waiting for server to patch... (send SIGUSR1 when done)\n");
    fflush(stdout);

    /* Wait for signal */
    signal(SIGUSR1, sig_handler);
    while (!g_patched) {
        usleep(100000);
    }

    /* Read back — server should have written DEADBEEF */
    /* Make readable first */
    raw_mprotect(code, 4096, PROT_READ);
    uint8_t* p = (uint8_t*)code;
    printf("readback: %02x%02x%02x%02x\n", p[0], p[1], p[2], p[3]);
    if (p[0] == 0xDE && p[1] == 0xAD && p[2] == 0xBE && p[3] == 0xEF) {
        printf("RESULT: server pwrite WORKS!\n");
    } else {
        printf("RESULT: patch not found (still %02x%02x%02x%02x)\n", p[0], p[1], p[2], p[3]);
    }

    raw_munmap(code, 4096);
    return 0;
}

/* ---- Mode 3: patch — server writes target's /proc/<pid>/mem ---- */
static int test_patch(int target_pid, unsigned long target_addr) {
    printf("=== server patch mode ===\n");
    printf("target pid=%d addr=0x%lx\n", target_pid, target_addr);

    /* Open /proc/<pid>/mem */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", target_pid);

    long fd = raw_openat(AT_FDCWD, path, O_RDWR);
    printf("raw openat(%s, O_RDWR) = %ld %s\n", path, fd, fd >= 0 ? "OK" : "FAILED");

    if (fd < 0) {
        printf("RESULT: cannot open %s (errno=%ld)\n", path, -fd);
        return 1;
    }

    /* Read before */
    uint8_t before[4] = {0};
    long r = raw_pread(fd, before, 4, (long)target_addr);
    printf("before: pread ret=%ld data=%02x%02x%02x%02x\n", r, before[0], before[1], before[2], before[3]);

    /* pwrite to R-X page */
    uint8_t patch[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    long n = raw_pwrite(fd, patch, 4, (long)target_addr);
    printf("pwrite ret=%ld %s\n", n, n == 4 ? "OK" : "FAILED");

    /* Read after */
    uint8_t after[4] = {0};
    r = raw_pread(fd, after, 4, (long)target_addr);
    printf("after:  pread ret=%ld data=%02x%02x%02x%02x\n", r, after[0], after[1], after[2], after[3]);

    raw_close(fd);

    if (n == 4 && after[0] == 0xDE) {
        printf("RESULT: cross-process pwrite to R-X page WORKS!\n");
    } else {
        printf("RESULT: cross-process pwrite FAILED (errno=%ld)\n", -n);
    }

    /* Signal target to check */
    kill(target_pid, SIGUSR1);
    printf("sent SIGUSR1 to pid %d\n", target_pid);

    return n == 4 ? 0 : 1;
}

/* ---- Mode 4: fork — child=target, parent=server, all-in-one ---- */
static int test_fork(void) {
    printf("=== fork cross-process pwrite test ===\n");

    /* Allocate R-X page BEFORE fork so both see it */
    void* code = (void*)raw_mmap(0, 4096, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)code < 0) {
        printf("mmap FAILED\n");
        return 1;
    }
    memset(code, 0x00, 4096);
    raw_mprotect(code, 4096, PROT_READ | PROT_EXEC);
    printf("code page at %p (R-X)\n", code);

    /* pipe for child→parent addr sync */
    int pipefd[2];
    pipe(pipefd);

    pid_t child = fork();
    if (child < 0) {
        printf("fork FAILED\n");
        return 1;
    }

    if (child == 0) {
        /* ---- CHILD (target) ---- */
        close(pipefd[0]);
        /* tell parent our pid + addr */
        unsigned long addr = (unsigned long)code;
        write(pipefd[1], &addr, sizeof(addr));
        close(pipefd[1]);

        /* Wait for parent to patch */
        signal(SIGUSR1, sig_handler);
        while (!g_patched) usleep(50000);

        /* Verify */
        raw_mprotect(code, 4096, PROT_READ);
        uint8_t* p = (uint8_t*)code;
        printf("[child pid=%d] readback: %02x%02x%02x%02x\n",
               (int)getpid(), p[0], p[1], p[2], p[3]);
        if (p[0] == 0xDE && p[1] == 0xAD && p[2] == 0xBE && p[3] == 0xEF)
            printf("[child] RESULT: server cross-process pwrite WORKS!\n");
        else
            printf("[child] RESULT: patch NOT found\n");
        _exit(0);
    }

    /* ---- PARENT (server/root) ---- */
    close(pipefd[1]);
    unsigned long child_addr;
    read(pipefd[0], &child_addr, sizeof(child_addr));
    close(pipefd[0]);

    printf("[parent] child pid=%d addr=0x%lx\n", (int)child, child_addr);
    usleep(100000); /* let child settle */

    /* Open /proc/<child>/mem */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)child);
    long fd = raw_openat(AT_FDCWD, path, O_RDWR);
    printf("[parent] openat(%s) = %ld %s\n", path, fd, fd >= 0 ? "OK" : "FAILED");

    if (fd < 0) {
        printf("[parent] RESULT: cannot open %s (errno=%ld)\n", path, -fd);
        kill(child, SIGKILL);
        return 1;
    }

    /* Read before */
    uint8_t before[4] = {0};
    raw_pread(fd, before, 4, (long)child_addr);
    printf("[parent] before: %02x%02x%02x%02x\n", before[0], before[1], before[2], before[3]);

    /* pwrite to child's R-X page — NO mprotect! */
    uint8_t patch[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    long n = raw_pwrite(fd, patch, 4, (long)child_addr);
    printf("[parent] pwrite ret=%ld %s\n", n, n == 4 ? "OK" : "FAILED");

    /* Read after */
    uint8_t after[4] = {0};
    raw_pread(fd, after, 4, (long)child_addr);
    printf("[parent] after:  %02x%02x%02x%02x\n", after[0], after[1], after[2], after[3]);
    raw_close(fd);

    if (n == 4 && after[0] == 0xDE)
        printf("[parent] RESULT: cross-process pwrite to R-X WORKS!\n");
    else
        printf("[parent] RESULT: cross-process pwrite FAILED (errno=%ld)\n", -n);

    /* Signal child to verify */
    kill(child, SIGUSR1);
    int status;
    waitpid(child, &status, 0);

    raw_munmap(code, 4096);
    return n == 4 ? 0 : 1;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("usage:\n");
        printf("  %s self     — pwrite /proc/self/mem\n", argv[0]);
        printf("  %s fork     — cross-process: parent pwrite child's /proc/pid/mem\n", argv[0]);
        printf("  %s target   — be target, wait for external patch\n", argv[0]);
        printf("  %s patch <pid> <hex_addr>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "self") == 0) {
        return test_self();
    } else if (strcmp(argv[1], "fork") == 0) {
        return test_fork();
    } else if (strcmp(argv[1], "target") == 0) {
        return test_target();
    } else if (strcmp(argv[1], "patch") == 0 && argc >= 4) {
        int pid = atoi(argv[2]);
        unsigned long addr = strtoul(argv[3], NULL, 16);
        return test_patch(pid, addr);
    } else {
        printf("unknown mode: %s\n", argv[1]);
        return 1;
    }
}
