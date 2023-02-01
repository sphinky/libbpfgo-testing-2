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
	
	USE(prog);
	/*_, err = prog.AttachKprobe("__x64_sys_execve")
	if err != nil {
		os.Exit(-1)
	}
	*/

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

	fmt.Printf("----------------------------------------------------------");

	for {
		event := <-eventsChannel
		//process id
		pid := int(binary.LittleEndian.Uint32(event[0:4])) // Treat first 4 bytes as LittleEndian Uint32
		//user id
		uid := int(binary.LittleEndian.Uint32(event[4:8])) 
		//process name
		comm := string(bytes.TrimRight(event[8:100], "\x00")) // Remove excess 0's from comm, treat as string
		msg := string(bytes.TrimRight(event[100:], "\x00")) // Remove excess 0's from comm, treat as string
	    //fmt.Printf("|\t\t %d \t\t| %d \t\t| %v \t\t| %v \t\t|\n", "PID", "UID", "Name", "MSG"")
		fmt.Printf("|%d \t| %d \t| %v \t| %v \t|\n", pid, uid, comm, msg)
	}

	rb.Stop()
	rb.Close()
}

func use(x interface{}) {
	return 0;
}