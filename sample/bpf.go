package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 tracer ./c/sample.bpf.c -- -I./c/headers -Wno-address-of-packed-member -fno-stack-protector
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 tracer ./c/sample.bpf.c -- -I./c/headers -Wno-address-of-packed-member -fno-stack-protector
