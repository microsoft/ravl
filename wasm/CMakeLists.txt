# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

find_program(CMAKE_C_COMPILER emcc REQUIRED)
find_program(CMAKE_CXX_COMPILER em++ REQUIRED)

project(ravl LANGUAGES CXX C ASM)

cmake_minimum_required(VERSION 3.14)
set(CMAKE_CXX_STANDARD 20)

set(RAVL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

option(OE "enable Open Enclave" ON)
option(SGX "enable SGX" ON)
option(SEV_SNP "enable SEV/SNP" ON)
option(TESTS "enable testing" ON)
option(PROFILE "enable profiling" OFF)

set(RAVL_SRC ${RAVL_DIR}/ravl.cpp)
set(RAVL_INCLUDE ${RAVL_DIR}/3rdparty ${RAVL_DIR} /data/cwinter/emsdk/upstream/emscripten/cache/sysroot/include)
set(RAVL_DEFS)
set(RAVL_LIB_DEPS)
set(RAVL_LIB_DIRS)
set(RAVL_LINK_OPTS -fexceptions -sFETCH)
set(RAVL_FLAGS -sNO_DISABLE_EXCEPTION_CATCHING -fexceptions)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".so")

list(APPEND RAVL_DEFS HAVE_OPENSSL)
list(APPEND RAVL_LIB_DEPS crypto)
list(APPEND RAVL_INCLUDE ${CMAKE_BINARY_DIR}/openssl/include)
list(APPEND RAVL_LIB_DIRS ${CMAKE_BINARY_DIR}/openssl)

if (SGX)
  list(APPEND RAVL_DEFS HAVE_SGX)
  list(APPEND RAVL_SRC ${RAVL_DIR}/ravl_sgx.cpp)
endif()

if (OE)
  list(APPEND RAVL_DEFS HAVE_OPEN_ENCLAVE)
  list(APPEND RAVL_SRC ${RAVL_DIR}/ravl_oe.cpp)
endif()

if (SEV_SNP)
  list(APPEND RAVL_DEFS HAVE_SEV_SNP)
  list(APPEND RAVL_SRC ${RAVL_DIR}/ravl_sev_snp.cpp)
endif()

list(APPEND RAVL_SRC ${RAVL_DIR}/ravl_url_requests.cpp ravl_requests_fetch.cpp)

set(CMAKE_EXECUTABLE_SUFFIX_CXX .html)
add_executable(ravl ${RAVL_SRC} test_main.cpp)
target_include_directories(ravl PRIVATE ${RAVL_INCLUDE})
target_compile_definitions(ravl PRIVATE ${RAVL_DEFS})
target_compile_options(ravl PRIVATE ${RAVL_FLAGS})
target_link_libraries(ravl PRIVATE ${RAVL_LIB_DEPS})
target_link_directories(ravl PRIVATE ${RAVL_LIB_DIRS})
target_link_options(ravl PRIVATE ${RAVL_LINK_OPTS})
