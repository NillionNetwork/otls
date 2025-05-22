FROM ubuntu:22.04

# Set environment variables to avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies (including gRPC requirements)
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
    autoconf \
    libtool \
    pkg-config \
    libprotobuf-dev \
    protobuf-compiler \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create work directory
WORKDIR /opt/primus

# Install gRPC and protobuf
RUN git clone --recurse-submodules -b v1.46.0 --depth 1 --shallow-submodules https://github.com/grpc/grpc /opt/grpc \
    && cd /opt/grpc \
    && mkdir -p cmake/build \
    && cd cmake/build \
    && cmake -DgRPC_INSTALL=ON \
            -DgRPC_BUILD_TESTS=OFF \
            -DCMAKE_INSTALL_PREFIX=/usr/local \
            ../.. \
    && make -j$(nproc) \
    && make install \
    && ldconfig

# Clone and build primus-emp
RUN git clone https://github.com/primus-labs/primus-emp.git && \
    cd primus-emp && \
    bash ./compile.sh && \
    cd ..

# Copy source code
COPY . /opt/primus/otls/
WORKDIR /opt/primus/otls

# Compile protobuf definitions (assuming protos directory exists in your project)
RUN mkdir -p proto && \
    if [ -d "proto" ]; then \
        protoc -I proto --cpp_out=proto --grpc_out=proto \
        --plugin=protoc-gen-grpc=$(which grpc_cpp_plugin) \
        proto/*.proto; \
    fi

# Set include paths for gRPC and protobuf
ENV CPLUS_INCLUDE_PATH="/opt/primus/otls/proto:${CPLUS_INCLUDE_PATH}"
ENV LIBRARY_PATH="/usr/local/lib:${LIBRARY_PATH}"
ENV LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}"

# Build otls
RUN bash ./compile.sh /opt/primus/primus-emp

# Create a directory for binaries if it doesn't exist
RUN mkdir -p bin

# Set the working directory to otls
WORKDIR /opt/primus/otls

# Default command that allows interactive use of the container
CMD ["/bin/bash"]