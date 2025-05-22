cmake_minimum_required(VERSION 3.10)
project(pvss-client)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set paths to find gRPC
set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH};/usr/local")
list(APPEND CMAKE_MODULE_PATH "/usr/local/lib/cmake/grpc")

# Find required packages
find_package(Protobuf REQUIRED)
find_package(gRPC CONFIG REQUIRED)
if(NOT gRPC_FOUND)
  message(FATAL_ERROR "gRPC not found. Please install gRPC using the provided install_grpc.sh script.")
endif()

# Get proto files
get_filename_component(pvss_proto "../proto/pvss.proto" ABSOLUTE)
get_filename_component(pvss_proto_path "${pvss_proto}" PATH)

# Generate C++ code from proto files
set(pvss_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/pvss.pb.cc")
set(pvss_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/pvss.pb.h")
set(pvss_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/pvss.grpc.pb.cc")
set(pvss_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/pvss.grpc.pb.h")

add_custom_command(
    OUTPUT "${pvss_proto_srcs}" "${pvss_proto_hdrs}" "${pvss_grpc_srcs}" "${pvss_grpc_hdrs}"
    COMMAND ${Protobuf_PROTOC_EXECUTABLE}
    ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
         --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
         -I "${pvss_proto_path}"
         --plugin=protoc-gen-grpc="$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
         "${pvss_proto}"
    DEPENDS "${pvss_proto}"
)

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

# Define the client executable
add_executable(pvss_client
    client.cpp
    ${pvss_proto_srcs}
    ${pvss_grpc_srcs}
)

# Link with required libraries
target_link_libraries(pvss_client
    gRPC::grpc++
    gRPC::grpc++_reflection
    protobuf::libprotobuf
) 