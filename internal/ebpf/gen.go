package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type kray_event_t Bpf ../../bpf/tracer.c
