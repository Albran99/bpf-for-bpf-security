# Use Alpine as the base image
FROM alpine:latest

RUN apk update && apk add --no-cache \
    build-base \
    clang \
    llvm \
    linux-headers \
    git \
    cmake \
    pkgconfig \
    libbpf-dev \
    gcc \
    libpcap-dev \
    iproute2 \
    iputils \
    bash \
    curl \
    make \
    bpftool \
    git

RUN apk add --no-cache libcap
RUN git clone https://github.com/libbpf/libbpf.git /home/libbpf
RUN cd /home/libbpf/src && make

COPY ./xdp /home/xdp
COPY ./ksyscall /home/ksyscall
# Set the entrypoint to bash (or any command you prefer)
ENTRYPOINT ["/bin/bash"]
