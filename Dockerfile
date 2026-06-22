# Use the same OS as your host for consistency
FROM ubuntu:24.04

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install basic tools needed for Goose and your script
RUN apt-get update && apt-get install -y \
    curl \
    python3 \
    python3-pip \
    procps \
    z3 \
    git \
    git-lfs \
    && rm -rf /var/lib/apt/lists/*

## 2 steps for ark compiliation
# 1. Install system dependencies
# 2. Comprehensive Toolchain Installation
RUN apt-get update && apt-get install -y \
    # Core Build Systems
    cmake \
    ninja-build \
    make \
    pkg-config \
    build-essential \
    # Compilers & Multilib (Crucial for Ark/Cross-compiling)
    gcc-multilib \
    g++-multilib \
    clang \
    llvm \
    # Scripting Languages & Headers
    python3 \
    python3-pip \
    python3-dev \
    ruby \
    ruby-dev \
    nodejs \
    npm \
    # Formal Verification & Logic (Z3 dependencies)
    z3 \
    libgmp-dev \
    # Libraries for Ark/C++ Extensions
    libssl-dev \
    libffi-dev \
    libyaml-dev \
    zlib1g-dev \
    libc++1 \
    libc++-dev \
    libc6-dev-i386 \
    lib32ncurses-dev \
    lib32z1-dev \
    # Version Control & Networking
    curl \
    wget \
    git \
    git-lfs \
    ssh \
    gnupg \
    # Utilities
    procps \
    unzip \
    zip \
    bison \
    flex \
    rsync \
    && rm -rf /var/lib/apt/lists/*

# 3. Python & Ruby Environment Finalization
RUN ln -s /usr/bin/python3 /usr/bin/python && \
    pip3 install --break-system-packages \
    requests \
    setuptools \
    z3-solver \
    pyyaml

# let pip know we know we are installing as root and ignore it
ENV PIP_ROOT_USER_ACTION=ignore
RUN pip3 install requests --break-system-packages

# 2. Install 'repo' tool
RUN mkdir -p /usr/local/bin && \
    curl -fsSL https://gitee.com/oschina/repo/raw/fork_flow/repo-py3 > /usr/local/bin/repo && \
    chmod a+x /usr/local/bin/repo

# Install Goose
RUN curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | CONFIGURE=false bash
RUN mv /root/.local/bin/goose /usr/local/bin/goose

RUN curl -fsSL https://opencode.ai/install | bash

# Download and run the rustup installer script
# -sSf ensures curl fails quietly but safely on server errors
# -y bypasses the interactive confirmation prompt
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Add the Rust binaries to the system PATH environment variable
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /workspace
#ENTRYPOINT ["goose"]