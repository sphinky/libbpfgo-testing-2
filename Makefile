all: vmlinux.h bpf_target go_target

vmlinux.h:
	/usr/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

bpf_target: simple.bpf.c
	clang -g -O2 -c -target bpf -o simple.bpf.o simple.bpf.c

go_target: simple.bpf.o main.go
	CC=gcc CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="/usr/lib/x86_64-linux-gnu/libbpf.a" go build -o libbpfgo-prog

clean:
	rm simple.bpf.o libbpfgo-prog vmlinux.h
