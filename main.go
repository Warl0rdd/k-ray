package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/common-nighthawk/go-figure"
	"k-ray/internal"
	"k-ray/internal/ebpf"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// cool logo as hell
	figure.NewFigure("K-Ray", "doom", true).Print()

	fmt.Println("[*] Starting...")

	fmt.Println("[*] Removing memory lock...")
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Println("[ERROR] Failed to remove memory lock:", err)
		os.Exit(1)
	}

	fmt.Println("[*] Loading BPF objects into the kernel...")
	var objs ebpf.BpfObjects
	if err := ebpf.LoadBpfObjects(&objs, nil); err != nil {
		fmt.Println("[ERROR] Failed to load bpf objects:", err)
		os.Exit(1)
	}
	defer objs.Close()

	fmt.Println("[*] Attaching kprobe...")
	probe, err := link.Kprobe("tcp_v4_connect", objs.TcpV4Connect, nil)
	if err != nil {
		fmt.Println("[ERROR] Failed to attach kprobe:", err)
		os.Exit(1)
	}
	defer probe.Close()

	fmt.Println("[*] Attaching kretprobe...")
	retprobe, err := link.Kretprobe("tcp_v4_connect", objs.TcpV4ConnectRet, nil)
	if err != nil {
		fmt.Println("[ERROR] Failed to attach kretprobe:", err)
		os.Exit(1)
	}
	defer retprobe.Close()

	fmt.Println("[*] Opening the ring buffer...")
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fmt.Println("[ERROR] Failed to create ring buffer reader:", err)
		_ = probe.Close()
		os.Exit(1)
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		fmt.Println("[*] Exiting...")
		os.Exit(0)
	}()

	fmt.Println("[*] Started successfully!")
	var event ebpf.BpfKrayEventT
	for {
		record, err := rd.Read()
		if err != nil {
			fmt.Println("[ERROR] Failed to read ring buffer:", err)
			_ = probe.Close()
			_ = rd.Close()
			os.Exit(1)
		}

		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			fmt.Println("[ERROR] Failed to parse event:", err)
			continue
		}

		fmt.Printf("[*] PID %d (%s): %s -> %s:%d\n", event.Pid, internal.CommToString(event.Comm), internal.IntToIP(event.Saddr), internal.IntToIP(event.Daddr), internal.Ntohs(event.Dport))
	}
}
