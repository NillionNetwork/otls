find_package(emp-zk)

find_path(OTLS_INCLUDE_DIR backend/switch.h)
find_library(OTLS_LIBRARY NAMES otls)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(otls DEFAULT_MSG OTLS_INCLUDE_DIR)

if(OTLS_FOUND)
    set(OTLS_INCLUDE_DIRS ${EMP-ZK_INCLUDE_DIRS} ${OTLS_INCLUDE_DIR})
    set(OTLS_LIBRARIES ${EMP-ZK_LIBRARIES} ${OTLS_LIBRARY})
endif()
