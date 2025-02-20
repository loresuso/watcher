package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf program bpf/program.bpf.c

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs programObjects
	if err := loadProgramObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	links := make([]link.Link, 0)
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	// Attach Deny Exec program.
	l, err := link.AttachLSM(link.LSMOptions{
		Program: objs.DenyExec,
	})
	if err != nil {
		log.Fatal("Attaching LSM:", err)
	}
	links = append(links, l)

	// Attach File Open program.
	l, err = link.AttachLSM(link.LSMOptions{
		Program: objs.FileOpen,
	})
	if err != nil {
		log.Fatal("Attaching LSM:", err)
	}
	links = append(links, l)

	// Attach BPF program.
	l, err = link.AttachLSM(link.LSMOptions{
		Program: objs.Bpf,
	})
	if err != nil {
		log.Fatal("Attaching bpf:", err)
	}
	links = append(links, l)

	// Attach task_kill program.
	l, err = link.AttachLSM(link.LSMOptions{
		Program: objs.TaskKill,
	})
	if err != nil {
		log.Fatal("Attaching task_kill:", err)
	}
	links = append(links, l)

	// Attach path_unlink program.
	l, err = link.AttachLSM(link.LSMOptions{
		Program: objs.PathUnlink,
	})
	if err != nil {
		log.Fatal("Attaching path_unlink:", err)
	}
	links = append(links, l)

	err = objs.programMaps.UidMap.Update(uint32(1001), uint32(0), 0)
	if err != nil {
		log.Fatal("Updating map:", err)
	}

	log.Println("eBPF program attached. Press Ctrl+C to exit.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	time.AfterFunc(60*time.Second, func() {
		cancel()
	})

	select {
	case <-ctx.Done():
		log.Println("Timeout reached, exiting...")

	case <-stop:
		log.Println("Signal received, exiting...")
	}

}
