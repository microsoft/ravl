# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

find_program(CMAKE_C_COMPILER emcc REQUIRED)
find_program(CMAKE_CXX_COMPILER emcc REQUIRED)

project(ravl LANGUAGES CXX C ASM)

cmake_minimum_required(VERSION 3.14)
set(CMAKE_CXX_STANDARD 20)

set(RAVL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

# option(OPENSSL "enable OpenSSL" ON)
option(OE "enable Open Enclave" ON)
option(SGX "enable SGX" ON)
option(SEV_SNP "enable SEV/SNP" ON)
option(TESTS "enable testing" ON)
option(PROFILE "enable profiling" OFF)

set(RAVL_SRC ${RAVL_DIR}/ravl.cpp)
set(RAVL_DEFS HAVE_OPENSSL)
set(RAVL_LIB_DEPS crypto)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".so")

if (SGX)
list(APPEND RAVL_SRC ${RAVL_DIR}/ravl_sgx.cpp)
endif()

if (SEV_SNP)
list(APPEND RAVL_SRC ${RAVL_DIR}/ravl_sev_snp.cpp)
endif()

list(APPEND RAVL_SRC ${RAVL_DIR}/ravl_requests.cpp)

set(CMAKE_EXECUTABLE_SUFFIX_CXX .html)
add_executable(ravl ${RAVL_SRC} test_main.cpp)
target_include_directories(ravl PRIVATE ${RAVL_DIR} ${RAVL_DIR}/3rdparty ${CMAKE_BINARY_DIR}/openssl/include)
target_compile_definitions(ravl PRIVATE ${RAVL_DEFS})
target_compile_options(ravl PRIVATE -sNO_DISABLE_EXCEPTION_CATCHING -fexceptions)
target_link_libraries(ravl PRIVATE ${RAVL_LIB_DEPS})
target_link_directories(ravl PRIVATE ${CMAKE_BINARY_DIR}/openssl)
target_link_options(ravl PRIVATE -fexceptions)
