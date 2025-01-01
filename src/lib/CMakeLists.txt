# TODO 14: Remove mysqrt.cxx from the list of sources

# TODO 1: Add a library called MathFunctions with sources MathFunctions.cxx
# and mysqrt.cxx

add_library(DSMLib
    dsm_lock.cpp
    main.cpp
    dsm_node.cpp
    injection.s 
    user_mprotect.cpp
)

target_include_directories(DSMLib PUBLIC
    "${CMAKE_SOURCE_DIR}/src/include"
)

