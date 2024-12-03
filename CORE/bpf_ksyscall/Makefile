TARGET = bpf_trace
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_OBJ = ${TARGET}.bpf.o
USER_C = ${TARGET}.c
USER_SKEL = ${TARGET}.skel.h

all: $(TARGET) $(BPF_OBJ)
.PHONY: all

$(TARGET): $(USER_C) $(USER_SKEL)
	gcc -Wall -o $(TARGET) $(USER_C) -L ~/libbpf/src/ -l:libbpf.a -lelf -lz

%.bpf.o: %.bpf.c vmlinux.h
	clang \
		-target bpf \
		-mllvm -bpf-stack-size=4096 \
		-D __TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-Wall \
		-O2 -g\
		-c $< -o $@
	llvm-strip -g $@

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	- rm -f $(TARGET) $(BPF_OBJ) $(USER_SKEL) vmlinux.h
.PHONY: clean

