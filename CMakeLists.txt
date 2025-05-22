cmake_minimum_required (VERSION 3.0)
project (otls)
set(NAME "otls")

# Add gRPC support option
option(ENABLE_GRPC "Enable gRPC support" OFF)

IF(ENABLE_WASM)
  set(CMAKE_FOLDER ${CMAKE_INSTALL_PREFIX})
  include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

  find_package(OpenSSL REQUIRED)
  include_directories(${OPENSSL_INCLUDE_DIR})

  set(EMP-TOOL_INCLUDE_DIRS ${CMAKE_INSTALL_PREFIX}/include)
  set(EMP-TOOL_LIBRARIES ${CMAKE_INSTALL_PREFIX}/lib/libemp-tool.a ${OPENSSL_LIBRARIES})
  include_directories(${EMP-TOOL_INCLUDE_DIRS})

  set(EMP-OT_INCLUDE_DIRS ${CMAKE_INSTALL_PREFIX}/include)
  set(EMP-OT_LIBRARIES "")
  include_directories(${EMP-OT_INCLUDE_DIRS})

  set(EMP-ZK_INCLUDE_DIRS ${CMAKE_INSTALL_PREFIX}/include)
  set(EMP-ZK_LIBRARIES ${CMAKE_INSTALL_PREFIX}/lib/libemp-zk.a)
  include_directories(${EMP-ZK_INCLUDE_DIRS})
ELSE()
  find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
  include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

  find_package(emp-ot REQUIRED)
  include_directories(${EMP-OT_INCLUDE_DIRS})

  find_package(emp-zk REQUIRED)
  include_directories(${EMP-ZK_INCLUDE_DIRS})
ENDIF()

# Add gRPC support if enabled
if(ENABLE_GRPC)
  find_package(Protobuf REQUIRED)
  find_package(gRPC CONFIG QUIET)
  
  if(NOT gRPC_FOUND)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GRPC REQUIRED grpc++)
    pkg_check_modules(PROTOBUF REQUIRED protobuf)
    set(GRPC_LIBRARIES ${GRPC_LIBRARIES} ${PROTOBUF_LIBRARIES})
  else()
    set(GRPC_LIBRARIES gRPC::grpc++ gRPC::grpc)
  endif()
  
  # Add proto build directory to include path
  set(PROTO_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/proto")
  include_directories(${PROTO_BUILD_DIR})
  
  # Define proto source files
  set(PROTO_SOURCES
    ${PROTO_BUILD_DIR}/pvss.pb.cc
    ${PROTO_BUILD_DIR}/pvss.grpc.pb.cc
  )
  
  # Add preprocessor definition to enable gRPC features in code
  add_definitions(-DENABLE_GRPC)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
set(sources
  backend/switch.cpp
  cipher/utils.cpp
)
option(LOAD_CIRCUIT_FROM_MEM "" OFF)
IF(LOAD_CIRCUIT_FROM_MEM)
  add_definitions(-DLOAD_CIRCUIT_FROM_MEM=1)
  list(APPEND sources
    cipher/circuit_files/aes128_ks_data.cpp
    cipher/circuit_files/aes128_with_ks_data.cpp
  )
ENDIF()
option(USE_PRIMUS_EMP "use primus emp" OFF)
IF(USE_PRIMUS_EMP)
  add_definitions(-DUSE_PRIMUS_EMP=1)
ENDIF()
add_compile_options(-fPIC)
IF(USE_PRIMUS_EMP)
add_library(otls ${sources})
ELSE()
add_library(otls SHARED ${sources})
ENDIF()
target_link_libraries(otls ${EMP-TOOL_LIBRARIES} ${EMP-ZK_LIBRARIES} dl)

install(FILES cmake/otls-config.cmake DESTINATION cmake/)
install(TARGETS otls DESTINATION lib)

install(DIRECTORY backend cipher protocol DESTINATION include)

option(ENABLE_OTLS_TEST "otls test" ON)
IF(ENABLE_OTLS_TEST)
  ENABLE_TESTING()
  ADD_SUBDIRECTORY(test)
ENDIF()
