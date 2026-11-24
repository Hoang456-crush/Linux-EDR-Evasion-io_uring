# Linux EDR Evasion & Telemetry Assessment Container
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install compilation toolchain and testing utilities
RUN apt-get update && apt-get install -y \
    build-essential \
    liburing-dev \
    git \
    curl \
    netcat-openbsd \
    strace \
    auditd \
    procps \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . /workspace

# Compile modular lab and shared libraries
RUN cd /workspace/src && make

WORKDIR /workspace/src
CMD ["./evasion_lab", "--mode", "benchmark", "--safe-mode"]
