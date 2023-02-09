package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	bpf "github.com/aquasecurity/tracee/libbpfgo"
	"os"
)

func main() {

	bpfModule, err := bpf.NewModuleFromFile("probe.bpf.o")
	if err != nil {
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()
	prog2, err := bpfModule.GetProgram("kprobe__vfs_rename")
	if err != nil {
		os.Exit(-1)
	}

	_, err = prog2.AttachKprobe("vfs_rename")
	if err != nil {
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		os.Exit(-1)
	}

	rb.Start()

	fmt.Printf("----------------------------------------------------------\n")
	fmt.Printf("| %10v \t| %10v \t| %30v \t| %30v \t|\n", "PID", "UID", "Name", "MSG")

	for {
		event := <-eventsChannel
		// process id
		pid := int(binary.LittleEndian.Uint32(event[0:4])) // Treat first 4 bytes as LittleEndian Uint32
		// user id
		uid := int(binary.LittleEndian.Uint32(event[4:8]))
		// process name
		// Remove excess 0's from comm, treat as string
		comm := string(bytes.TrimRight(event[8:200], "\x00"))
		// Remove excess 0's from comm, treat as string
		msg := string(bytes.TrimRight(event[200:], "\x00"))

		fmt.Printf("| %10d \t| %10d \t| %30v \t| %30v \t|\n", pid, uid, comm, msg)
	}

	rb.Stop()
	rb.Close()
}
