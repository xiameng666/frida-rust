/*
 * Zymbiote notification stub — ARM64 position-independent shellcode.
 *
 * Called as: setArgV0Native(JNIEnv* x0, jobject x1, jstring x2)
 *
 * Flow:
 *   1. getuid() — if UID != target, tail-call original function
 *   2. Restore ArtMethod entry_point (*slot_addr = original_func)
 *   3. Connect to abstract Unix socket @<socket_name>
 *   4. Send our PID (4 bytes)
 *   5. Block on read(1 byte) until injector signals completion
 *   6. Close socket, tail-call original setArgV0Native
 *
 * All I/O uses raw SVC #0 syscalls — no libc function pointers needed.
 *
 * StubData layout (located after code, found via marker):
 *   +0x00  mark[16]       "/alone12345678\0\0"
 *   +0x10  original_func  (u64)
 *   +0x18  slot_addr      (u64)
 *   +0x20  uid            (u32)
 *   +0x24  socket_name    (108 bytes, null-terminated)
 *
 * Build:
 *   clang --target=aarch64-linux-android31         \
 *       -nostdlib -nostartfiles -nodefaultlibs      \
 *       -fPIC -O2 -c stub.S -o stub.o
 *   llvm-objcopy -O binary -j .text stub.o stub.bin
 */

/* --- syscall numbers (aarch64) --- */
#define __NR_close      57
#define __NR_read       63
#define __NR_write      64
#define __NR_getpid    172
#define __NR_getuid    174
#define __NR_socket    198
#define __NR_connect   203

#define AF_UNIX   1
#define SOCK_STREAM 1
#define EINTR     4

/* --- StubData field offsets --- */
#define OFF_ORIG_FUNC  0x10
#define OFF_SLOT_ADDR  0x18
#define OFF_UID        0x20
#define OFF_SOCK_NAME  0x24

/* --- sockaddr_un size on stack --- */
#define SOCKADDR_SIZE  112

.text
.align 2
.global _start
_start:
    /* ---- save frame + callee-saved ---- */
    stp     x29, x30, [sp, #-0x40]!
    mov     x29, sp
    stp     x19, x20, [sp, #0x10]
    stp     x21, x22, [sp, #0x20]
    stp     x23, x24, [sp, #0x30]

    /* save original function args */
    mov     x19, x0                     // JNIEnv*
    mov     x20, x1                     // jobject
    mov     x21, x2                     // jstring

    /* load StubData address (PC-relative) */
    adr     x22, stub_data

    /* ---- step 1: getuid() ---- */
    mov     x8, #__NR_getuid
    svc     #0
    mov     w23, w0                     // current uid

    /* compare with target uid */
    ldr     w24, [x22, #OFF_UID]
    cmp     w23, w24
    b.ne    .Lcall_original             // not our target → skip

    /* ---- step 2: restore ArtMethod slot ---- */
    ldr     x0, [x22, #OFF_ORIG_FUNC]  // original setArgV0Native
    ldr     x1, [x22, #OFF_SLOT_ADDR]  // ArtMethod entry_point addr
    str     x0, [x1]                    // *slot = original (COW in child)

    /* ---- step 3: socket(AF_UNIX, SOCK_STREAM, 0) ---- */
    mov     x0, #AF_UNIX
    mov     x1, #SOCK_STREAM
    mov     x2, #0
    mov     x8, #__NR_socket
    svc     #0
    mov     x23, x0                     // save socket fd
    tbnz    x0, #63, .Lcall_original    // if negative → error, skip

    /* ---- build sockaddr_un on stack ---- */
    sub     sp, sp, #SOCKADDR_SIZE

    /* zero sun_family + first byte of sun_path */
    stp     xzr, xzr, [sp]             // zero first 16 bytes (covers sun_family area)

    /* sun_family = AF_UNIX */
    mov     w0, #AF_UNIX
    strh    w0, [sp]

    /* sun_path[0] = 0 (abstract socket namespace) — already zeroed */

    /* copy socket_name from StubData → sun_path[1..] */
    add     x0, x22, #OFF_SOCK_NAME    // source
    add     x1, sp, #3                  // dest: &sun_path[1]
.Lcopy:
    ldrb    w2, [x0], #1
    strb    w2, [x1], #1
    cbnz    w2, .Lcopy

    /* ---- step 4: connect(fd, &addr, computed_len) ---- */
    /* x1 = past the NUL terminator after copy loop
     * addr_len = x1 - sp - 1  (exclude trailing NUL so it matches bind) */
    mov     x4, sp
    sub     x2, x1, x4
    sub     x2, x2, #1
    mov     x0, x23                     // socket fd
    mov     x1, sp                      // sockaddr_un*
    mov     x8, #__NR_connect
    svc     #0
    tbnz    x0, #63, .Lcleanup         // connect failed

    /* ---- step 5: getpid() → write(fd, &pid, 4) ---- */
    mov     x8, #__NR_getpid
    svc     #0
    str     w0, [sp, #(SOCKADDR_SIZE - 4)]  // temp store pid

    mov     x0, x23                     // fd
    add     x1, sp, #(SOCKADDR_SIZE - 4)    // &pid
    mov     x2, #4
    mov     x8, #__NR_write
    svc     #0

    /* ---- step 6: read(fd, buf, 1) — block for "done" signal ---- */
.Lread:
    mov     x0, x23                     // fd
    add     x1, sp, #(SOCKADDR_SIZE - 4)
    mov     x2, #1
    mov     x8, #__NR_read
    svc     #0
    cmn     x0, #EINTR                  // interrupted?
    b.eq    .Lread                      // retry

.Lcleanup:
    /* close(fd) */
    mov     x0, x23
    mov     x8, #__NR_close
    svc     #0

    /* restore stack from sockaddr_un */
    add     sp, sp, #SOCKADDR_SIZE

.Lcall_original:
    /* restore original function args */
    mov     x0, x19
    mov     x1, x20
    mov     x2, x21

    /* load original function address for tail-call */
    ldr     x9, [x22, #OFF_ORIG_FUNC]

    /* restore callee-saved */
    ldp     x23, x24, [sp, #0x30]
    ldp     x21, x22, [sp, #0x20]
    ldp     x19, x20, [sp, #0x10]
    ldp     x29, x30, [sp], #0x40

    /* tail-call original setArgV0Native */
    br      x9

/* ---- data section (immediately after code) ---- */
.align 3
stub_data:
    .ascii  "/alone12345678\0\0"        /* +0x00: marker (16 bytes) */
    .quad   0                           /* +0x10: original_func */
    .quad   0                           /* +0x18: slot_addr */
    .word   0                           /* +0x20: uid */
    .space  108                         /* +0x24: socket_name[108] */
