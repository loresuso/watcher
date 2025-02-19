//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#define PATHLEN 256

char _license[] SEC("license") = "GPL";

SEC("lsm/bprm_creds_from_file")
int BPF_PROG(deny_exec, struct linux_binprm *bprm, int ret) {
  __u32 uid =
      bpf_get_current_uid_gid() & 0xFFFFFFFF; // Extract the lower 32 bits (UID)

  if (uid == 1001)
	return -EPERM;

  return 0;
}
