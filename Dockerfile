FROM debian:latest

# Define variables.
ARG GOVERSION=1.18.10
ARG ARCH=amd64

# Download development environment.
RUN apt-get update && \
    apt-get install -y \
        libbpf-dev \
        make \
        clang \
        llvm \
        libelf-dev \
        bpftool \
        gcc-multilib

# Install Go specific version.
RUN apt-get install -y wget && \
    wget https://golang.org/dl/go${GOVERSION}.linux-${ARCH}.tar.gz && \
    tar -xf go${GOVERSION}.linux-${ARCH}.tar.gz && \
    mv go/ /usr/local/ && \
    ln -s /usr/local/go/bin/go /usr/local/bin/ && \
    rm -rf go${GOVERSION}.linux-${ARCH}.tar.gz

# Setup working directory.
RUN mkdir -p /usr/include/bits
RUN mkdir -p /app
RUN cp -nr /usr/include/x86_64-linux-gnu/bits/* /usr/include/bits/

WORKDIR /app
COPY * ./

# Execute build command.
# CMD ["/bin/bash", "-c","/usr/bin/make all"]
 ENTRYPOINT ["make > /dev/null 2>&1 && ./runebpf"]

