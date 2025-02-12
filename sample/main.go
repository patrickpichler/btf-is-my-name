package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	spec, err := loadTracer()
	if err != nil {
		panic(err)
	}

	var progs tracerObjects

	if err := spec.LoadAndAssign(&progs, &ebpf.CollectionOptions{}); err != nil {
		panic(err.Error())
	}

	l, err := link.Tracepoint("raw_syscalls", "sys_enter", progs.DetectSyscallEnter, &link.TracepointOptions{
		Cookie: 0,
	})
	if err != nil {
		panic(err.Error())
	}
	defer l.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()

	<-ctx.Done()
}
