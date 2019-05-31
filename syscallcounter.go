package main

import (
	"fmt"
	"os"
	"text/tabwriter"
    "time"
	sec "github.com/seccomp/libseccomp-golang"
)

type syscallMetadata struct {
    count int
    dur time.Duration
}

type syscallCounter []syscallMetadata

const maxSyscalls = 303

func (s syscallCounter) init() syscallCounter {
	s = make(syscallCounter, maxSyscalls)
	return s
}

func (s syscallCounter) inc(syscallID uint64, dur time.Duration) error {
	if syscallID > maxSyscalls {
		return fmt.Errorf("invalid syscall ID (%x)", syscallID)
	}

	s[syscallID].count++
    s[syscallID].dur += dur
	return nil
}

func (s syscallCounter) print() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 8, ' ', tabwriter.AlignRight|tabwriter.Debug)
	for k, v := range s {
		if v.count > 0 {
			name, _ := sec.ScmpSyscall(k).GetName()
            fmt.Fprintf(w, "%s: %d\t%v\n", name, v.count, v.dur)
		}
	}
	w.Flush()
}

func (s syscallCounter) getName(syscallID uint64) string {
	name, _ := sec.ScmpSyscall(syscallID).GetName()
	return name
}
