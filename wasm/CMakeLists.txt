# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

find_program(CMAKE_C_COMPILER emcc REQUIRED)
find_program(CMAKE_CXX_COMPILER em++ REQUIRED)

project(ravl LANGUAGES CXX C ASM)

cmake_minimum_required(VERSION 3.14)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_VISIBILITY_PRESET default)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 0)


set(RAVL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(RAVL_SRC_DIR ${RAVL_DIR}/src)

if(NOT DEFINED ENV{EMSDK})
  message(FATAL_ERROR "This build requires empscripten, but the EMSDK environment variable is not defined.")
endif()

if (NOT EXISTS ${CMAKE_BINARY_DIR}/openssl)
  message(FATAL_ERROR "This build requires an emscripten build of OpenSSL, see ../openssl.sh")
endif()

set(RAVL_SRC ${RAVL_SRC_DIR}/ravl.cpp ${RAVL_SRC_DIR}/attestation.cpp)
set(RAVL_INCLUDE ${RAVL_DIR}/3rdparty ${RAVL_DIR}/include)
set(RAVL_DEFS)
set(RAVL_LIB_DEPS)
set(RAVL_LIB_DIRS)
set(RAVL_LINK_OPTS -fexceptions -sFETCH -sASYNCIFY)
set(RAVL_FLAGS -sNO_DISABLE_EXCEPTION_CATCHING -fexceptions)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".so")

list(APPEND RAVL_DEFS RAVL_HAVE_OPENSSL)
list(APPEND RAVL_LIB_DEPS crypto)
list(APPEND RAVL_INCLUDE ${CMAKE_BINARY_DIR}/openssl/include)
list(APPEND RAVL_LIB_DIRS ${CMAKE_BINARY_DIR}/openssl)

list(APPEND RAVL_SRC ${RAVL_SRC_DIR}/http_client.cpp http_client_fetch.cpp)

list(APPEND RAVL_DEFS RAVL_LIBRARY_BUILD)

set(CMAKE_EXECUTABLE_SUFFIX_CXX .html)
add_executable(ravl ${RAVL_SRC} test_main.cpp)
target_include_directories(ravl PRIVATE ${RAVL_INCLUDE})
target_compile_definitions(ravl PRIVATE ${RAVL_DEFS})
target_compile_options(ravl PRIVATE ${RAVL_FLAGS})
target_link_libraries(ravl PRIVATE ${RAVL_LIB_DEPS})
target_link_directories(ravl PRIVATE ${RAVL_LIB_DIRS})
target_link_options(ravl PRIVATE ${RAVL_LINK_OPTS})
