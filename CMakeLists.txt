# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This must be done before the `project` command.
if (UNIX)
  if (NOT DEFINED ENV{CC} AND NOT DEFINED CMAKE_C_COMPILER)
    find_program(CMAKE_C_COMPILER clang-10 clang)
  endif ()
  if (NOT DEFINED ENV{CXX} AND NOT DEFINED CMAKE_CXX_COMPILER)
    find_program(CMAKE_CXX_COMPILER clang++-10 clang++)
  endif ()
endif ()

project(ravl LANGUAGES CXX C ASM)

cmake_minimum_required(VERSION 3.14)
set(CMAKE_CXX_STANDARD 20)

set(RAVL_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(RAVL_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

option(OE "enable support for Open Enclave attestation reports" ON)
option(SGX "enable support for Intel SGX attestation reports" ON)
option(SEV_SNP "enable support for AMD SEV/SNP attestation reports" ON)
option(TESTS "enable tests" ON)
option(PROFILE "enable profiling" OFF)

option(USE_OE_VERIFIER "use the Open Enclave verifier directly (requires Open Enclave SDK)" OFF)

option(OE_TEST_ENCLAVE "enable Open Enclave test enclave (requires Open Enclave SDK)" OFF)
option(SGX_TEST_ENCLAVE "enable SGX test enclave (requires Intel SGX SDK)" OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".so")

set(RAVL_SRC ${RAVL_SRC_DIR}/url_requests.cpp ${RAVL_SRC_DIR}/ravl.cpp)
set(RAVL_INCLUDE 3rdparty ${RAVL_DIR}/include)
set(RAVL_DEFS)
set(RAVL_LIB_DEPS)
set(RAVL_LIB_DIRS)

find_package(OpenSSL REQUIRED)
list(APPEND RAVL_DEFS HAVE_OPENSSL)
list(APPEND RAVL_LIB_DEPS crypto)


if(SGX)
  list(APPEND RAVL_DEFS HAVE_SGX)
  list(APPEND RAVL_SRC ${RAVL_SRC_DIR}/sgx.cpp)
endif()

if(OE)
  list(APPEND RAVL_DEFS HAVE_OPEN_ENCLAVE)
  list(APPEND RAVL_SRC ${RAVL_SRC_DIR}/oe.cpp)

  if(USE_OE_VERIFIER)
    find_package(OpenEnclave REQUIRED)
    find_library(hostverify oehostverify PATHS ${OpenEnclave_DIR}/../host REQUIRED)
    list(APPEND RAVL_INCLUDE ${OE_INCLUDEDIR})
    list(APPEND RAVL_LIB_DIRS ${hostverify_DIR})
    list(APPEND RAVL_LIB_DEPS ${hostverify})
    list(APPEND RAVL_DEFS USE_OE_VERIFIER)
  endif()
endif()

if(SEV_SNP)
  list(APPEND RAVL_DEFS HAVE_SEV_SNP)
  list(APPEND RAVL_SRC ${RAVL_SRC_DIR}/sev_snp.cpp)
endif()

# TODO: make curl optional
find_package(CURL REQUIRED)
list(APPEND RAVL_LIB_DEPS curl)
list(APPEND RAVL_SRC ${RAVL_SRC_DIR}/url_requests_curl.cpp)

if(PROFILE)
  list(APPEND RAVL_FLAGS -g -pg)
  list(APPEND RAVL_LINK_OPTS -g -pg)
endif()

add_library(ravl STATIC)
target_sources(ravl PRIVATE ${RAVL_SRC})
target_include_directories(ravl INTERFACE .)
target_include_directories(ravl PRIVATE ${RAVL_INCLUDE})
target_compile_options(ravl PRIVATE ${RAVL_FLAGS})
target_compile_definitions(ravl PRIVATE ${RAVL_DEFS})
target_link_directories(ravl PRIVATE ${RAVL_LIB_DIRS})
target_link_libraries(ravl INTERFACE ${RAVL_LIB_DEPS})
target_link_options(ravl PRIVATE ${RAVL_LINK_OPTS})

add_library(ravl-shared SHARED)
target_sources(ravl-shared PRIVATE ${RAVL_SRC})
target_include_directories(ravl-shared INTERFACE .)
target_include_directories(ravl-shared PRIVATE PRIVATE ${RAVL_INCLUDE})
target_compile_options(ravl-shared PRIVATE ${RAVL_FLAGS})
target_compile_definitions(ravl-shared PRIVATE ${RAVL_DEFS})
target_link_directories(ravl-shared PRIVATE ${RAVL_LIB_DIRS})
target_link_libraries(ravl-shared INTERFACE ${RAVL_LIB_DEPS})
target_link_options(ravl-shared PRIVATE ${RAVL_LINK_OPTS})
set_target_properties(ravl-shared PROPERTIES OUTPUT_NAME ravl)

add_executable(ravl-cli ${RAVL_SRC_DIR}/cli.cpp)
target_include_directories(ravl-cli PUBLIC ${RAVL_DIR}/include)
set_target_properties(ravl-cli PROPERTIES OUTPUT_NAME ravl)

install(TARGETS ravl ravl-shared ravl-cli)

if(TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
