FROM ubuntu:22.04

# Set environment variables to avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Add build argument for curve selection with default value
ARG RELIC_CURVE=Ed25519
ARG BUILD_ON_MAC=no
ENV RELIC_CURVE=${RELIC_CURVE}
ENV BUILD_ON_MAC=${BUILD_ON_MAC}

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    libboost-all-dev \
    libgmp-dev \
    pkg-config \
    python3 \
    python3-pip \
    wget \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /opt

# Clone RELIC repository
RUN git clone https://github.com/relic-toolkit/relic.git

# Create target directory
RUN mkdir -p /opt/relic-target

WORKDIR /opt/relic-target

# Configure RELIC based on selected curve
RUN set -ex && \
    if [ "$RELIC_CURVE" = "BLS12-446" ]; then \
        echo "Building RELIC with BLS12-446 curve" && \
        if [ "$BUILD_ON_MAC" = "yes" ]; then \
            ARITH_BACKEND="x64-asm" ; \
        else \
            ARITH_BACKEND="x64-asm-7l" ; \
        fi && \
        cmake ../relic \
            -DWSIZE=64 \
            -DRAND=UDEV \
            -DSHLIB=OFF \
            -DSTBIN=ON \
            -DTIMER=CYCLE \
            -DCHECK=off \
            -DVERBS=off \
            -DARITH=${ARITH_BACKEND} \
            -DFP_PRIME=446 \
            -DFP_METHD="INTEG;INTEG;INTEG;MONTY;JMPDS;JMPDS;SLIDE" \
            -DCFLAGS="-O3 -funroll-loops -fomit-frame-pointer -finline-small-functions -march=native -mtune=native" \
            -DFP_PMERS=off \
            -DFP_QNRES=on \
            -DFPX_METHD="INTEG;INTEG;LAZYR" \
            -DEP_PLAIN=off -DEP_SUPER=off -DPP_METHD="LAZYR;OATEP" ; \
    elif [ "$RELIC_CURVE" = "Ed25519" ]; then \
        echo "Building RELIC with Ed25519" && \
        if [ "$BUILD_ON_MAC" = "yes" ]; then \
            ARITH_BACKEND="x64-asm" ; \
        else \
            ARITH_BACKEND="x64-hacl-25519" ; \
        fi && \
        cmake ../relic \
            -DCHECK=off \
            -DARITH=${ARITH_BACKEND} \
            -DFP_PRIME=255 \
            -DFP_QNRES=off \
            -DSTRIP=on \
            -DEC_METHD="EDDIE" \
            -DFP_METHD="INTEG;INTEG;INTEG;QUICK;JMPDS;JMPDS;SLIDE" \
            -DED_METHD='EXTND;LWNAF;COMBS;INTER' \
            -DCFLAGS="-O3 -funroll-loops -fomit-frame-pointer -march=native -mtune=native" \
            -DWITH="DV;MD;BC;BN;FP;ED;EC;CP" ; \
    else \
        echo "Unknown curve: $RELIC_CURVE" && exit 1 ; \
    fi


# Build and install RELIC
RUN make -j$(nproc) && \
    make install && \
    ldconfig

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
