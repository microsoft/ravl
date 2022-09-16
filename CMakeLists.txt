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

option(OE "enable support for Open Enclave attestation reports" ON)
option(SGX "enable support for Intel SGX attestation reports" ON)
option(SEV_SNP "enable support for AMD SEV/SNP attestation reports" ON)
option(TESTS "enable tests" ON)
option(PROFILE "enable profiling" OFF)

option(USE_OE_VERIFIER "use the Open Enclave verifier directly (requires Open Enclave SDK)" OFF)

option(OE_TEST_ENCLAVE "enable Open Enclave test enclave (requires Open Enclave SDK)" OFF)
option(SGX_TEST_ENCLAVE "enable SGX test enclave (requires Intel SGX SDK)" OFF)

add_library(ravl)
target_include_directories(ravl INTERFACE .)
target_include_directories(ravl PRIVATE 3rdparty)

add_executable(ravlcli cli.cpp)
target_include_directories(ravlcli PUBLIC .)

install(TARGETS ravl ravlcli)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".so")

find_package(OpenSSL REQUIRED)
set(RAVL_SRC ravl.cpp ravl_requests.cpp ravl_requests_threaded.cpp)
set(RAVL_DEFS HAVE_OPENSSL)
set(RAVL_LIB_DEPS crypto)

if(SGX)
  list(APPEND RAVL_DEFS HAVE_SGX)
  list(APPEND RAVL_SRC ravl_sgx.cpp)
endif()

if(OE)
  list(APPEND RAVL_DEFS HAVE_OPEN_ENCLAVE)
  list(APPEND RAVL_SRC ravl_oe.cpp)

  if(USE_OE_VERIFIER)
    find_package(OpenEnclave REQUIRED)
    find_library(hostverify oehostverify PATHS ${OpenEnclave_DIR}/../host REQUIRED)
    target_include_directories(ravl PRIVATE ${OE_INCLUDEDIR})
    target_link_directories(ravl PRIVATE ${hostverify_DIR})
    list(APPEND RAVL_LIB_DEPS ${hostverify})
    list(APPEND RAVL_DEFS USE_OE_VERIFIER)
  endif()
endif()

if(SEV_SNP)
  list(APPEND RAVL_DEFS HAVE_SEV_SNP)
  list(APPEND RAVL_SRC ravl_sev_snp.cpp)
endif()

find_package(CURL REQUIRED)
list(APPEND RAVL_LIB_DEPS curl)
list(APPEND RAVL_SRC ravl_requests_curl.cpp)

target_sources(ravl PRIVATE ${RAVL_SRC})
target_link_libraries(ravl INTERFACE ${RAVL_LIB_DEPS})
target_compile_definitions(ravl PRIVATE ${RAVL_DEFS})

if(PROFILE)
  target_compile_options(ravl PRIVATE -g -pg)
  target_link_options(ravl PRIVATE -g -pg)
endif()

if(TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
