#!/bin/bash
set -e

# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential autoconf libtool pkg-config cmake
sudo apt-get install -y libssl-dev

# Clone the gRPC repository
if [ ! -d "grpc" ]; then
  git clone --recurse-submodules -b v1.45.0 https://github.com/grpc/grpc
fi

cd grpc

# Build and install gRPC
mkdir -p cmake/build
cd cmake/build
cmake -DgRPC_INSTALL=ON \
      -DgRPC_BUILD_TESTS=OFF \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      ../..
make -j4
sudo make install

# Update the linker cache
sudo ldconfig

echo "gRPC has been installed successfully!" 