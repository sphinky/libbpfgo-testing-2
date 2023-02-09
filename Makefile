all: vmlinux.h bpf_target go_target stdout

vmlinux.h:
	/usr/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

bpf_target: probe.bpf.c
	clang -g -O2 -c -target bpf -o probe.bpf.o probe.bpf.c

go_target: probe.bpf.o main.go
	CC=gcc CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="/usr/lib/x86_64-linux-gnu/libbpf.a" go build main.go

stdout: main_stdout.go
	CC=gcc CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="/usr/lib/x86_64-linux-gnu/libbpf.a" go build main_stdout.go

clean:
	rm probe.bpf.o run_ebpf run_ebpf_stdout vmlinux.h
