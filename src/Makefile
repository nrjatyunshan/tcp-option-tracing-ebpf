CLANG ?= clang

default: deps
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	${CLANG}  -g -O2 -I .  -target bpf -c tot.bpf.c -o tot.bpf.o
	bpftool gen skeleton tot.bpf.o > tot.skel.h
	gcc main.c -lbpf -o tot
deps:
	@bpftool version > /dev/null
	@ls /sys/kernel/btf/vmlinux > /dev/null

clean:
	rm vmlinux.h tot.bpf.o tot.skel.h tot

.PHONY: default clean deps