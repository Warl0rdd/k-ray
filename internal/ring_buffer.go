package internal

import (
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"k-ray/internal/ebpf"
	"os"
	"sync"
)

const maxEvents = 100

type EventRingBuffer struct {
	mu     sync.RWMutex
	events [maxEvents]ebpf.BpfKrayEventT
	head   int
	count  int
}

func (b *EventRingBuffer) Add(e ebpf.BpfKrayEventT) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.events[b.head] = e
	b.head = (b.head + 1) % maxEvents
	if b.count < maxEvents {
		b.count++
	}
}

func (b *EventRingBuffer) PrintTable() {
	b.mu.RLock()
	defer b.mu.RUnlock()

	fmt.Print("\033[H\033[2J")

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)

	t.AppendHeader(table.Row{"PID", "COMM", "SRC", "DST"})

	for i := 0; i < b.count; i++ {
		idx := (b.head - 1 - i + maxEvents) % maxEvents
		e := b.events[idx]

		src := fmt.Sprintf("%s:%d", IntToIP(e.Saddr), e.Sport)
		dst := fmt.Sprintf("%s:%d", IntToIP(e.Daddr), Ntohs(e.Dport))

		t.AppendRow(table.Row{e.Pid, CommToString(e.Comm), src, dst})
	}

	t.SetStyle(table.StyleColoredBlackOnRedWhite)
	t.Render()
}
