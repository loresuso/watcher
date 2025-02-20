//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#define PATH_LEN 256
#define TASK_COMM_LEN 16

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

SEC("lsm/file_open") 
int BPF_PROG(file_open, struct file *file) {
	char path[PATH_LEN];
	__u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	bpf_d_path(&file->f_path, path, PATH_LEN);
	if (bpf_strncmp(path, 11, "/etc/passwd") == 0 && uid == 1002) {
		return -EPERM;
	}
	bpf_printk("uid: %d, path: %s\n", uid, path);
	return 0;
}

SEC("lsm/bpf")
int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size) {
	if (cmd == BPF_PROG_LOAD) {
		return -EPERM;
	} else if (cmd == BPF_MAP_CREATE) {
		return -EACCES;
	}
	return 0;
}

SEC("lsm/task_kill")
int BPF_PROG(task_kill, struct task_struct *p, struct kernel_siginfo *info,
		       int sig, const struct cred *cred) {
	
	if (sig != 9)
		return 0;

	if (bpf_strncmp(p->comm, 5, "falco") == 0){
		return -EPERM;
	}

	return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(path_unlink, struct path *dir, struct dentry *dentry) {
	char path[PATH_LEN];
	bpf_d_path(dir, path, PATH_LEN);

	if (bpf_strncmp(path, PATH_LEN, "/home/vagrant") == 0){
		return -EPERM;
	}

	return 0;
}