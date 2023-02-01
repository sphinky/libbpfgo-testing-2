package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"context"

	bpf "github.com/aquasecurity/tracee/libbpfgo"

	"strconv"

	common "github.com/oracle/oci-go-sdk/v65/common"
	helpers "github.com/oracle/oci-go-sdk/v65/example/helpers"
	streaming "github.com/oracle/oci-go-sdk/v65/streaming"

	
	auth "github.com/oracle/oci-go-sdk/v65/common/auth"
)

type EbpfEvent struct {
	pid int
	uid  int
	pname string
	msg string
}

const ociMessageEndpoint = "https://cell-1.streaming.us-ashburn-1.oci.oraclecloud.com"
const ociStreamOcid = "ocid1.stream.oc1.iad.amaaaaaazvuhnbqangngfi52tognl6bcjwviefusj44kvuk6eccf37tvy6sa"

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

	xevent := EbpfEvent{}

	for {
		event := <-eventsChannel
		//process id
		pid := int(binary.LittleEndian.Uint32(event[0:4])) // Treat first 4 bytes as LittleEndian Uint32
		//user id
		uid := int(binary.LittleEndian.Uint32(event[4:8])) 
		//process name
		comm := string(bytes.TrimRight(event[8:200], "\x00")) // Remove excess 0's from comm, treat as string
		msg := string(bytes.TrimRight(event[200:], "\x00")) // Remove excess 0's from comm, treat as string
	   
		xevent.pid = pid
		xevent.uid = uid
		xevent.pname =comm
		xevent.msg =msg

		//fmt.Printf("|%d \t| %d \t| %v \t| %v \t|\n", pid, uid, comm, msg);
		putMsgInStream(ociMessageEndpoint, ociStreamOcid, &xevent);
	}

	rb.Stop()
	rb.Close()
}

func USE(x interface{}) {
	
}

func putMsgInStream(streamEndpoint string, streamOcid string, xevent *EbpfEvent) {

	provider, err := auth.InstancePrincipalConfigurationProvider()
	helpers.FatalIfError(err)

	streamClient, err := streaming.NewStreamClientWithConfigurationProvider(provider, streamEndpoint)
	helpers.FatalIfError(err)
	
	fmt.Println("Stream endpoint for put msg api is: " + streamEndpoint)
	
	// Create a request and dependent object(s).


	putMsgReq := streaming.PutMessagesRequest{
		StreamId: common.String(streamOcid),
		PutMessagesDetails: streaming.PutMessagesDetails{
			
			Messages: []streaming.PutMessagesDetailsEntry{
				{
					Key: []byte(xevent.pid),
					Value: []byte(strconv.itoa(xevent.pid)+"|"+strconv(xevent.uid)+"|"+xevent.pname+"|"+xevent.msg+"|")				}			}		},	}
		


	// Send the request using the service client
	putMsgResp, err := streamClient.PutMessages(context.Background(), putMsgReq)
	helpers.FatalIfError(err)

	// Retrieve value from the response.
	fmt.Println(putMsgResp)
}