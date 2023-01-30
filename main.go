package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
)

func main() {

	bpfModule, err := bpf.NewModuleFromFile("simple.bpf.o")
	if err != nil {
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()
	prog, err := bpfModule.GetProgram("kprobe__sys_execve")
	if err != nil {
		os.Exit(-1)
	}

	_, err = prog.AttachKprobe("__x64_sys_execve")
	if err != nil {
		os.Exit(-1)
	}

	prog, err := bpfModule.GetProgram("kprobe__vfs_write")
	if err != nil {
		os.Exit(-1)
	}

	_, err = prog.AttachKprobe("vfs_write")
	if err != nil {
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		os.Exit(-1)
	}

	rb.Start()

	for {
		event := <-eventsChannel
		pid := int(binary.LittleEndian.Uint32(event[0:4])) // Treat first 4 bytes as LittleEndian Uint32
		uid := int(binary.LittleEndian.Uint32(event[4:8])) // Remove excess 0's from comm, treat as string
		comm := string(bytes.TrimRight(event[8:], "\x00")) // Remove excess 0's from comm, treat as string
		fmt.Printf("%d, %d, %v: %v\n", pid, uid, comm, "this process and user are attempting to create a new user namespace")
	}

	rb.Stop()
	rb.Close()
}