FROM --platform=linux/amd64 rust:1.87-bookworm

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /workspace

# Copy the project files
COPY . .

# Set up Rust toolchain (use the version specified in rust-toolchain file)
RUN rustup default $(cat rust-toolchain)

# Pre-build dependencies to cache them
RUN cargo fetch

# Default command
CMD ["/bin/bash"]
