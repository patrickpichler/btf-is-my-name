#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024 /* 1 MB */);
} events SEC(".maps");

struct event {
  u32 payload_size;
};

// Force BTF for event struct to be exported.
const struct event *unused_event __attribute__((unused));

struct data {
  char comm[16];
};

struct c {
  int data[10];
} __attribute__((preserve_access_index));

struct sample {
  int a;
  int b;
  struct c *c;
} __attribute__((preserve_access_index));

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 32);
  __type(key, u32);
  __type(value, struct data);
} data SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int detect_syscall_enter(struct trace_event_raw_sys_enter *ctx) {
  struct task_struct *t = (void *)bpf_get_current_task();
  // bpf_printk("hello, %d", BPF_CORE_READ(t, pid));

  // u64 time = bpf_ktime_get_ns();
  //
  // struct data val = {0};
  // BPF_CORE_READ_INTO(&val.comm, t, comm);

  u64 start_time = 0;
  bpf_core_read(&start_time, sizeof(start_time), t->start_boottime);

  bpf_printk("%lu", start_time);

  // char comm[16];
  // bpf_probe_read_kernel(&comm, sizeof(start_time), &t->comm);
  // bpf_printk("%s", comm);

  // u32 key = time % 32;
  //
  // bpf_map_update_elem(&data, &key, &val, BPF_ANY);
  //
  // if (bpf_core_type_exists(struct sample)) {
  //   struct sample *s = (void *)bpf_get_current_task();
  //   bpf_printk("hello, %d", BPF_CORE_READ(s, c, data[10]));
  // }

  return 0;
}
