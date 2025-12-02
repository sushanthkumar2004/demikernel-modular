FROM ubuntu:22.04

# Install core dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    cmake \
    git \
    curl \
    python3 \
    python3-pip \
    clang \
    llvm \
    pkg-config \
    libnuma-dev \
    libpcap-dev \
    libssl-dev \
    libelf-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /demikernel
