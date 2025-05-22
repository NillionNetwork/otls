FROM ubuntu:22.04

# Set environment variables to avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    libboost-all-dev \
    libgmp-dev \
    python3 \
    python3-pip \
    wget \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create work directory
WORKDIR /opt/primus

# Clone and build primus-emp
RUN git clone https://github.com/primus-labs/primus-emp.git && \
    cd primus-emp && \
    bash ./compile.sh && \
    cd ..

# Clone and build otls
COPY . /opt/primus/otls/
WORKDIR /opt/primus/otls
RUN bash ./compile.sh /opt/primus/primus-emp

# Create a directory for binaries if it doesn't exist
RUN mkdir -p bin

# Set the working directory to otls
WORKDIR /opt/primus/otls

# Default command that allows interactive use of the container
CMD ["/bin/bash"] 