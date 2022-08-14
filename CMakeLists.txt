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

cmake_minimum_required(VERSION 3.11)
set(CMAKE_CXX_STANDARD 17)

set(RAVL_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# option(OPENSSL "enable OpenSSL" ON)
option(OE "enable Open Enclave" ON)
option(TESTS "enable testing" ON)
option(PROFILE "enable profiling" OFF)

add_library(ravl ravl.cpp)
target_include_directories(ravl INTERFACE .)
target_include_directories(ravl PRIVATE 3rdparty)

add_executable(ravlcli cli.cpp)
target_include_directories(ravlcli PUBLIC .)

install(TARGETS ravl ravlcli)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".so")

find_package(OpenSSL REQUIRED)
set(RAVL_DEFS HAVE_OPENSSL)
set(RAVL_LIB_DEPS crypto)


if(OE)  
  find_package(OpenEnclave REQUIRED)    
  find_library(hostverify oehostverify PATHS ${OpenEnclave_DIR}/../host REQUIRED)  
  target_sources(ravl PRIVATE ravl_oe.cpp)
  list(APPEND RAVL_DEFS HAVE_OPEN_ENCLAVE)
  target_link_directories(ravl PRIVATE ${hostverify_DIR})
  target_include_directories(ravl PRIVATE ${OE_INCLUDEDIR})
  list(APPEND RAVL_LIB_DEPS ${hostverify})
endif()

target_link_libraries(ravl INTERFACE ${RAVL_LIB_DEPS})
target_compile_definitions(ravl PRIVATE ${RAVL_DEFS})

if(TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
