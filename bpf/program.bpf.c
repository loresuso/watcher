//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#define PATHLEN 256

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 256);
} uid_map SEC(".maps");

SEC("lsm/bprm_creds_from_file")
int BPF_PROG(deny_exec, struct linux_binprm *bprm, int ret) {
	// Extract the lower 32 bits (UID)
  	__u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	if (bpf_map_lookup_elem(&uid_map, &uid)) {
		return -EPERM;
	}
  	
	return 0;
}
