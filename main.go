package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	bpf "github.com/aquasecurity/tracee/libbpfgo"

	"context"
	"strconv"

	common "github.com/oracle/oci-go-sdk/v36/common"
	helpers "github.com/oracle/oci-go-sdk/v36/example/helpers"
	streaming "github.com/oracle/oci-go-sdk/v36/streaming"
)

type ebpfEvent struct {
	pid int
	uid  int
	pname string
	msg string
}

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

	//fmt.Printf("----------------------------------------------------------\n");
	//fmt.Printf("| %d \t| %d \t| %v \t| %v \t|\n", "PID", "UID", "Name", "MSG"");

	for {
		event := <-eventsChannel
		//process id
		pid := int(binary.LittleEndian.Uint32(event[0:4])) // Treat first 4 bytes as LittleEndian Uint32
		//user id
		uid := int(binary.LittleEndian.Uint32(event[4:8])) 
		//process name
		comm := string(bytes.TrimRight(event[8:200], "\x00")) // Remove excess 0's from comm, treat as string
		msg := string(bytes.TrimRight(event[200:], "\x00")) // Remove excess 0's from comm, treat as string
	   
		event := ebpfEvent{pid := pid,uid:= uid,comm :=comm,msg:=msg);
		//fmt.Printf("|%d \t| %d \t| %v \t| %v \t|\n", pid, uid, comm, msg);
		putMsgInStream(ociMessageEndpoint, ociStreamOcid, event);
	}

	rb.Stop()
	rb.Close()
}

func USE(x interface{}) {
	
}

const ociMessageEndpoint = "<stream_message_endpoint>"
const ociStreamOcid = "<stream_OCID>"
const ociConfigFilePath = "<config_file_path>"
const ociProfileName = "<config_file_profile_name>"


func putMsgInStream(streamEndpoint string, streamOcid string, event ebpfEvent) {
	fmt.Println("Stream endpoint for put msg api is: " + streamEndpoint)

	provider, err := common.ConfigurationProviderFromFileWithProfile(ociConfigFilePath, ociProfileName, "")
	helpers.FatalIfError(err)

	streamClient, err := streaming.NewStreamClientWithConfigurationProvider(provider, streamEndpoint)
	helpers.FatalIfError(err)

	// Create a request and dependent object(s).

	putMsgReq := streaming.PutMessagesRequest{
		StreamId: common.String(streamOcid),
		PutMessagesDetails: streaming.PutMessagesDetails{
			
			Messages: []streaming.PutMessagesDetailsEntry{
				{
					Key: []byte("key dummy-0-" + strconv.Itoa(i)),
					Value: []byte(event.pid+"|"+event.uid+"|"+event.comm+"|"+event.msg);
				}
			}
		},
	}

	// Send the request using the service client
	putMsgResp, err := streamClient.PutMessages(context.Background(), putMsgReq)
	helpers.FatalIfError(err)

	// Retrieve value from the response.
	fmt.Println(putMsgResp)
}