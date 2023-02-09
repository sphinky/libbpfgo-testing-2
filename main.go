package main

import "C"

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"strconv"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
	common "github.com/oracle/oci-go-sdk/v65/common"
	auth "github.com/oracle/oci-go-sdk/v65/common/auth"
	helpers "github.com/oracle/oci-go-sdk/v65/example/helpers"
	streaming "github.com/oracle/oci-go-sdk/v65/streaming"
)

type EbpfEvent struct {
	pid   int
	uid   int
	pname string
	msg   string
}

const ociMessageEndpoint = "https://cell-1.streaming.us-ashburn-1.oci.oraclecloud.com"
const ociStreamOcid = "ocid1.stream.oc1.iad.amaaaaaazvuhnbqangngfi52tognl6bcjwviefusj44kvuk6eccf37tvy6sa"

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

	ebpfEvent := EbpfEvent{}

	for {
		event := <-eventsChannel
		// process id
		// treat first 4 bytes as LittleEndian Uint32
		pid := int(binary.LittleEndian.Uint32(event[0:4]))
		// user id
		uid := int(binary.LittleEndian.Uint32(event[4:8]))
		// process name
		// remove excess 0's from comm, treat as string
		comm := string(bytes.TrimRight(event[8:200], "\x00"))
		// remove excess 0's from comm, treat as string
		msg := string(bytes.TrimRight(event[200:], "\x00"))

		ebpfEvent.pid = pid
		ebpfEvent.uid = uid
		ebpfEvent.pname = comm
		ebpfEvent.msg = msg

		putMsgInStream(ociMessageEndpoint, ociStreamOcid, &ebpfEvent)
	}

	rb.Stop()
	rb.Close()
}

func putMsgInStream(streamEndpoint string, streamOcid string, ebpfEvent *EbpfEvent) {

	provider, err := auth.InstancePrincipalConfigurationProvider()
	helpers.FatalIfError(err)

	streamClient, err := streaming.NewStreamClientWithConfigurationProvider(provider, streamEndpoint)
	helpers.FatalIfError(err)

	// fmt.Println("Stream endpoint for put msg api is: " + streamEndpoint)
	// create a streaming request and dependent object(s).
	putMsgReq := streaming.PutMessagesRequest{
		StreamId: common.String(streamOcid),
		PutMessagesDetails: streaming.PutMessagesDetails{
			Messages: []streaming.PutMessagesDetailsEntry{
				{
					Key:   []byte(strconv.Itoa(ebpfEvent.pid)),
					Value: []byte(strconv.Itoa(ebpfEvent.pid) + "|" + strconv.Itoa(ebpfEvent.uid) + "|" + ebpfEvent.pname + "|" + ebpfEvent.msg + "|"),
				},
			},
		},
	}

	putMsgResp, err := streamClient.PutMessages(context.Background(), putMsgReq)
	helpers.FatalIfError(err)
	USE(putMsgResp)

	// retrieve value from the response.
	// fmt.Println(putMsgResp)
}

func USE(x interface{}) {}
