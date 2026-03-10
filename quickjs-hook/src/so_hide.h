/*
 * so_hide.h - Hide injected SO from linker data structures
 *
 * Removes the SO from:
 *   1. soinfo linked list (linker internal)
 *   2. link_map chain (_r_debug->r_map, used by dl_iterate_phdr)
 *   3. ELF header in memory (magic bytes + header zeroed)
 *
 * All writes go through server pwrite (no mprotect, no ProtectedDataGuard).
 */

#ifndef SO_HIDE_H
#define SO_HIDE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return bitmask for so_hide_execute */
#define SO_HIDE_SOLIST    (1 << 0)  /* Removed from soinfo linked list */
#define SO_HIDE_LINKMAP   (1 << 1)  /* Removed from link_map chain */
#define SO_HIDE_ELFHDR    (1 << 2)  /* ELF header erased */

/*
 * Initialize SO hiding subsystem.
 * Parses linker64 ELF to resolve internal symbols (solist, _r_debug).
 *
 * @param server_fd  Patcher server socket fd (for pwrite/pread)
 * @return           0 on success, negative on error
 */
int so_hide_init(int server_fd);

/*
 * Hide a loaded SO by name (substring match).
 *
 * @param so_name  Substring to match in SO path (e.g. "xm-jit-cache")
 * @return         Bitmask of SO_HIDE_* flags, or negative on error
 */
int so_hide_execute(const char* so_name);

/*
 * Test function: logs dl_iterate_phdr enumeration before and after hiding.
 * Output goes to __android_log_print (logcat tag "XiaM-hide").
 *
 * @param so_name  Substring to match
 */
void so_hide_test(const char* so_name);

#ifdef __cplusplus
}
#endif

#endif /* SO_HIDE_H */
