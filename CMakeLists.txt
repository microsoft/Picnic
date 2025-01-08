cmake_minimum_required(VERSION 3.21)
project(Picnic C)

set(CMAKE_C_STANDARD 99)

# WARNING_FLAGS=-Wall -Wextra -Wpedantic -Wshadow
# we need to remove -Werror since there are two unused functions in KeccakP-1600-reference.c that causes warnings.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Wshadow")
# CFLAGS= -O2 -march=native $(WARNING_FLAGS) -std=gnu99 -D__LINUX__ -D__X64__ -I./sha3
# NISTKATFLAGS = -Wno-sign-compare -Wno-unused-but-set-variable -Wno-unused-parameter -Wno-unused-result
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-sign-compare -Wno-unused-but-set-variable -Wno-unused-parameter -Wno-unused-result")
# add other configs for aarch64
IF (${CMAKE_SYSTEM_PROCESSOR} MATCHES "(aarch64)|(arm64)")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a+simd+crypto+crc -D _ARM64_")
ELSE ()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native -D _AMD64_")
ENDIF ()

# build type
IF (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
ENDIF ()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")
IF (${CMAKE_BUILD_TYPE} MATCHES Debug)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -ggdb")
ELSEIF (${CMAKE_BUILD_TYPE} MATCHES Release)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
ENDIF ()

add_subdirectory(sha3)

add_library(
        picnic
        SHARED
        hash.c
        lowmc_constants.c
        picnic.c
        picnic_impl.c
        picnic3_impl.c
        picnic_types.c
        tree.c
)

target_include_directories(
        picnic
        PUBLIC
        sha3
)

target_link_libraries(
        picnic
        PUBLIC
        shake
)

# tool
add_executable(create_test_vectors create_test_vectors.c)
target_link_libraries(
        create_test_vectors
        PUBLIC
        picnic
)

add_executable(example example.c)
target_link_libraries(
        example
        PUBLIC
        picnic
)

# test cases
add_executable(kats_test kats_test.c)
target_link_libraries(
        kats_test
        PUBLIC
        picnic
)
add_executable(tree_test tree_test.c)
target_link_libraries(
        tree_test
        PUBLIC
        picnic
)
add_executable(unit_test unit_test.c)
target_link_libraries(
        unit_test
        PUBLIC
        picnic
)

enable_testing()
add_test(tree_test tree_test)
add_test(unit_test unit_test)
add_test(kats_test kats_test)