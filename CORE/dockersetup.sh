docker build -t test_container_bpftool .
docker run --rm --cap-add=CAP_BPF --cap-add=CAP_PERFMON --cap-add=CAP_NET_ADMIN --cap-add=CAP_SYS_ADMIN --cap-add=CAP_SYSLOG --rm -it test_container_bpftool
