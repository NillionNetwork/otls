cmake_minimum_required (VERSION 3.0)
project (otls)
set(NAME "otls")

# Find and configure RELIC
find_path(RELIC_INCLUDE_DIR relic.h
    PATHS
    /opt/relic-target/include
    /usr/local/include
    /usr/include
    /opt/relic/include
)

# Look for the static library
find_library(RELIC_LIBRARY relic_s
    PATHS
    /opt/relic-target/lib
    /usr/local/lib
    /usr/lib
    /opt/relic/lib
)

if(NOT RELIC_INCLUDE_DIR OR NOT RELIC_LIBRARY)
    message(FATAL_ERROR "RELIC not found! Please check your RELIC installation.")
endif()

include_directories(${RELIC_INCLUDE_DIR})
message(STATUS "Found RELIC: ${RELIC_LIBRARY}")

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
target_link_libraries(otls ${EMP-TOOL_LIBRARIES} ${EMP-ZK_LIBRARIES} ${RELIC_LIBRARY} gmp ssl crypto dl)

install(FILES cmake/otls-config.cmake DESTINATION cmake/)
install(TARGETS otls DESTINATION lib)

install(DIRECTORY backend cipher protocol DESTINATION include)

option(ENABLE_OTLS_TEST "otls test" ON)
IF(ENABLE_OTLS_TEST)
  ENABLE_TESTING()
  ADD_SUBDIRECTORY(test)
ENDIF()
