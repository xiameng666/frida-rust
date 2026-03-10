/*
 * test_raw_syscall.c — 测试原始系统调用
 *
 * 编译: just test-syscall
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

#define PROT_READ     0x1
#define PROT_WRITE    0x2
#define PROT_EXEC     0x4

#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20

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

/* ---- tests ---- */

static volatile uint8_t test_target[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

int main(void) {
    printf("=== raw syscall test ===\n");
    printf("pid = %d\n\n", (int)getpid());

    /* --- Test 1: raw mprotect --- */
    printf("[1] raw_mprotect test\n");
    void* mem = (void*)raw_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)mem < 0) {
        printf("    mmap FAILED (%ld)\n", (long)mem);
    } else {
        printf("    mmap OK: %p\n", mem);
        *(volatile uint8_t*)mem = 0x42;

        long rc = raw_mprotect(mem, 4096, PROT_READ | PROT_EXEC);
        printf("    mprotect(R-X) = %ld %s\n", rc, rc == 0 ? "OK" : "FAILED");

        rc = raw_mprotect(mem, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
        printf("    mprotect(RWX) = %ld %s\n", rc, rc == 0 ? "OK" : "FAILED");

        rc = raw_mprotect(mem, 4096, PROT_READ | PROT_EXEC);
        printf("    mprotect(R-X) = %ld %s\n", rc, rc == 0 ? "OK" : "FAILED");

        raw_munmap(mem, 4096);
    }

    /* --- Test 2: /proc/self/mem READ via libc --- */
    printf("\n[2] /proc/self/mem READ via libc open()\n");
    {
        FILE* f = fopen("/proc/self/mem", "r");
        if (!f) {
            printf("    libc fopen READ: FAILED (errno probably)\n");
        } else {
            uint8_t buf[8];
            fseek(f, (long)test_target, SEEK_SET);
            size_t n = fread(buf, 1, 8, f);
            fclose(f);
            if (n == 8 && buf[0] == 0x11 && buf[1] == 0x22)
                printf("    libc fread:  OK (read %zu bytes: %02x %02x ...)\n", n, buf[0], buf[1]);
            else
                printf("    libc fread:  FAILED (read %zu bytes)\n", n);
        }
    }

    /* --- Test 3: /proc/self/mem READ via raw syscall --- */
    printf("\n[3] /proc/self/mem READ via raw openat()\n");
    {
        long fd = raw_openat(AT_FDCWD, "/proc/self/mem", O_RDONLY);
        printf("    raw openat(O_RDONLY) = %ld %s\n", fd, fd >= 0 ? "OK" : "FAILED");
        if (fd >= 0) {
            uint8_t buf[8] = {0};
            long n = raw_pread(fd, buf, 8, (long)test_target);
            raw_close(fd);
            if (n == 8 && buf[0] == 0x11 && buf[1] == 0x22)
                printf("    raw pread:   OK (read %ld bytes: %02x %02x ...)\n", n, buf[0], buf[1]);
            else
                printf("    raw pread:   FAILED (ret=%ld, buf=%02x %02x)\n", n, buf[0], buf[1]);
        }
    }

    /* --- Test 4: /proc/self/mem WRITE via raw syscall --- */
    printf("\n[4] /proc/self/mem WRITE via raw openat()\n");
    {
        /* Allocate RW page, write via /proc/self/mem */
        void* page = (void*)raw_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if ((long)page < 0) {
            printf("    mmap FAILED\n");
        } else {
            *(volatile uint8_t*)page = 0xAA;

            /* Make it R-X first (simulate code page) */
            raw_mprotect(page, 4096, PROT_READ | PROT_EXEC);

            long fd = raw_openat(AT_FDCWD, "/proc/self/mem", O_WRONLY);
            printf("    raw openat(O_WRONLY) = %ld %s\n", fd, fd >= 0 ? "OK" : "FAILED");

            if (fd >= 0) {
                uint8_t val = 0xBB;
                long n = raw_pwrite(fd, &val, 1, (long)page);
                raw_close(fd);

                /* Read back — need to make readable first */
                raw_mprotect(page, 4096, PROT_READ);
                uint8_t readback = *(volatile uint8_t*)page;
                if (n == 1 && readback == 0xBB)
                    printf("    raw pwrite:  OK (wrote 0xBB, readback=0x%02x)\n", readback);
                else
                    printf("    raw pwrite:  FAILED (ret=%ld, readback=0x%02x)\n", n, readback);
            }
            raw_munmap(page, 4096);
        }
    }

    /* --- Test 5: /proc/self/mem WRITE to R-X page (the real scenario) --- */
    printf("\n[5] /proc/self/mem WRITE to R-X code page via raw syscall\n");
    {
        void* code = (void*)raw_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if ((long)code < 0) {
            printf("    mmap FAILED\n");
        } else {
            memset(code, 0x00, 4096);
            raw_mprotect(code, 4096, PROT_READ | PROT_EXEC);

            long fd = raw_openat(AT_FDCWD, "/proc/self/mem", O_RDWR);
            printf("    raw openat(O_RDWR) = %ld %s\n", fd, fd >= 0 ? "OK" : "FAILED");

            if (fd >= 0) {
                /* Try to write to the R-X page WITHOUT mprotect */
                uint8_t patch[4] = {0xDE, 0xAD, 0xBE, 0xEF};
                long n = raw_pwrite(fd, patch, 4, (long)code);
                printf("    raw pwrite to R-X page: ret=%ld %s\n", n, n == 4 ? "OK" : "FAILED");

                /* Read back via pread */
                uint8_t buf[4] = {0};
                long r = raw_pread(fd, buf, 4, (long)code);
                printf("    raw pread readback:     ret=%ld data=%02x%02x%02x%02x %s\n",
                       r, buf[0], buf[1], buf[2], buf[3],
                       (r == 4 && buf[0] == 0xDE) ? "OK" : "FAILED");
                raw_close(fd);
            }
            raw_munmap(code, 4096);
        }
    }

    printf("\n=== done ===\n");
    return 0;
}
