# MCP Security Dynamic Analysis Sandbox
# Based on Ubuntu 22.04 with eBPF/BCC support

FROM ubuntu:22.04

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies and BCC tools
RUN apt-get update && apt-get install -y \
    # BCC (BPF Compiler Collection) and eBPF tools
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc \
    linux-headers-generic \
    # Python 3.13 build dependencies
    software-properties-common \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    wget \
    curl \
    llvm \
    libncurses5-dev \
    libncursesw5-dev \
    xz-utils \
    tk-dev \
    libffi-dev \
    liblzma-dev \
    git \
    # Network tools for debugging
    net-tools \
    iproute2 \
    dnsutils \
    # Process monitoring tools
    procps \
    psmisc \
    && rm -rf /var/lib/apt/lists/*

# Use system Python 3 and install additional packages
RUN apt-get update && apt-get install -y \
    python3-pip \
    python3-setuptools \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install --no-cache-dir \
    docker \
    psutil

# Create directories for monitoring
RUN mkdir -p /target /logs /monitor

# Copy eBPF monitoring scripts
COPY monitors/ebpf_monitor.py /monitor/
COPY monitors/bpf_programs.c /monitor/
COPY monitors/entrypoint.sh /monitor/

# Make entrypoint executable
RUN chmod +x /monitor/entrypoint.sh

# Set working directory
WORKDIR /target

# Entrypoint: Start eBPF monitoring and execute target
ENTRYPOINT ["/monitor/entrypoint.sh"]
