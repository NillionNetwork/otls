#!/bin/bash
set -e

echo "Building and running the C++ to Rust gRPC demo"
echo "----------------------------------------------"

# Check if gRPC is installed
if [ ! -d "/usr/local/lib/cmake/grpc" ]; then
  echo "gRPC is not installed. Installing it now..."
  ./install_grpc.sh
fi

# Build the Rust server
echo "Building the Rust server..."
cd rust
cargo build
echo "Rust server built successfully!"

# Build the C++ client
echo "Building the C++ client..."
cd ../cpp
mkdir -p build
cd build
cmake .. || { echo "CMake configuration failed. Make sure gRPC is properly installed."; exit 1; }
make || { echo "Make failed."; exit 1; }
echo "C++ client built successfully!"

# Run the server in the background
echo "Starting the Rust server..."
cd ../../rust
cargo run &
SERVER_PID=$!

# Wait for the server to start
echo "Waiting for the server to start..."
sleep 3

# Run the client
echo "Running the C++ client..."
cd ../cpp/build
./pvss_client

# Clean up
echo "Cleaning up..."
kill $SERVER_PID || true

echo "Demo completed successfully!" 