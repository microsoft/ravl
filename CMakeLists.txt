# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This must be done before the `project` command.
if (UNIX)
  if (NOT DEFINED ENV{CC} AND NOT DEFINED CMAKE_C_COMPILER)
    find_program(CMAKE_C_COMPILER clang-10 clang)
    if(NOT CMAKE_C_COMPILER)
      find_program(CMAKE_C_COMPILER gcc-11 gcc)
    endif()
  endif ()
  if (NOT DEFINED ENV{CXX} AND NOT DEFINED CMAKE_CXX_COMPILER)
    find_program(CMAKE_CXX_COMPILER clang++-10 clang++)
    if(NOT CMAKE_CXX_COMPILER)
      find_program(CMAKE_CXX_COMPILER g++-11)
    endif()
  endif ()
endif ()

project(ravl LANGUAGES CXX C)

cmake_minimum_required(VERSION 3.14)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_VISIBILITY_PRESET default)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 0)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

list(APPEND RAVL_FLAGS -fPIC)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  list(APPEND RAVL_FLAGS -Wall
                         -Wextra
                         -Werror
                         -Wundef
                         -Wpedantic
                         -Wno-unused
                         -Wno-unused-parameter
                         -Wshadow)
  if(NOT DEFINED SAN)
    set(SAN on)
  endif()
endif()

set(RAVL_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(RAVL_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

option(TESTS "enable tests" ON)
option(PROFILE "enable profiling" OFF)
option(STATIC "build static library" ON)
option(SHARED "build shared library" OFF)
option(CLI "build the ravl CLI tool" ON)

option(USE_OE_VERIFIER "use the Open Enclave verifier directly (requires Open Enclave SDK)" OFF)

option(OE_TEST_ENCLAVE "enable Open Enclave test enclave (requires Open Enclave SDK)" OFF)
option(SGX_TEST_ENCLAVE "enable SGX test enclave (requires Intel SGX SDK)" OFF)
option(CURL "use libCURL for HTTP requests" ON)
option(OPENSSL "use OpenSSL as the crypto library" ON)
option(SAN "enable sanitizers" OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".so")

set(RAVL_SRC
  ${RAVL_SRC_DIR}/http_client.cpp
  ${RAVL_SRC_DIR}/ravl.cpp
  ${RAVL_SRC_DIR}/attestation.cpp
  ${RAVL_SRC_DIR}/request_tracker.cpp
  ${RAVL_SRC_DIR}/capi.cpp)
set(RAVL_INCLUDE 3rdparty ${RAVL_DIR}/include)
set(RAVL_DEFS RAVL_LIBRARY_BUILD)
set(RAVL_LIB_DEPS pthread)
set(RAVL_LIB_DIRS)

if(OPENSSL)
  find_package(OpenSSL REQUIRED)
  list(APPEND RAVL_DEFS RAVL_HAVE_OPENSSL)
  list(APPEND RAVL_LIB_DEPS crypto)
endif()

if(USE_OE_VERIFIER)
  find_package(OpenEnclave REQUIRED)
  find_library(hostverify oehostverify PATHS ${OpenEnclave_DIR}/../host REQUIRED)
  list(APPEND RAVL_INCLUDE ${OE_INCLUDEDIR})
  list(APPEND RAVL_LIB_DIRS ${hostverify_DIR})
  list(APPEND RAVL_LIB_DEPS ${hostverify})
  list(APPEND RAVL_DEFS RAVL_USE_OE_VERIFIER)
endif()

if(CURL)
  find_package(CURL REQUIRED)
  list(APPEND RAVL_LIB_DEPS curl)
  list(APPEND RAVL_SRC ${RAVL_SRC_DIR}/http_client_curl.cpp)
endif()

if(PROFILE)
  list(APPEND RAVL_FLAGS -g -pg)
  list(APPEND RAVL_LINK_OPTS -g -pg)
endif()


if(SAN)
  list(APPEND RAVL_FLAGS -fsanitize=undefined,address -fno-omit-frame-pointer)
  list(APPEND RAVL_LINK_OPTS -fsanitize=undefined,address)
endif()

set(RAVL_TARGETS)

if(STATIC)
  add_library(ravl STATIC ${RAVL_SRC})
  target_include_directories(ravl
    PRIVATE ${RAVL_INCLUDE}
    PUBLIC
      "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
      "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
  target_compile_options(ravl PRIVATE ${RAVL_FLAGS})
  target_compile_definitions(ravl PRIVATE ${RAVL_DEFS})
  target_link_directories(ravl PRIVATE ${RAVL_LIB_DIRS})
  target_link_libraries(ravl INTERFACE ${RAVL_LIB_DEPS})
  target_link_options(ravl PRIVATE ${RAVL_LINK_OPTS})
  target_include_directories(ravl INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
  list(APPEND RAVL_TARGETS ravl)
endif()

if(SHARED)
  add_library(ravl-shared SHARED ${RAVL_SRC})
  target_include_directories(ravl-shared
    PRIVATE ${RAVL_INCLUDE}
    PUBLIC
      "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
      "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
  target_compile_options(ravl-shared PRIVATE ${RAVL_FLAGS})
  target_compile_definitions(ravl-shared PRIVATE ${RAVL_DEFS})
  target_link_directories(ravl-shared PRIVATE ${RAVL_LIB_DIRS})
  target_link_libraries(ravl-shared INTERFACE ${RAVL_LIB_DEPS})
  target_link_options(ravl-shared PRIVATE ${RAVL_LINK_OPTS})
  set_target_properties(ravl-shared PROPERTIES OUTPUT_NAME ravl)
  target_include_directories(ravl-shared INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
  list(APPEND RAVL_TARGETS ravl-shared)
endif()

if(CLI)
  add_executable(ravl-cli ${RAVL_SRC_DIR}/cli.cpp)
  target_include_directories(ravl-cli PRIVATE ${RAVL_DIR}/include 3rdparty)
  set_target_properties(ravl-cli PROPERTIES OUTPUT_NAME ravl)
  target_link_libraries(ravl-cli PRIVATE $<BUILD_INTERFACE:ravl> pthread)
  target_link_options(ravl-cli PRIVATE ${RAVL_LINK_OPTS})
  list(APPEND RAVL_TARGETS ravl-cli)
endif()


include(GNUInstallDirs)

install(TARGETS ${RAVL_TARGETS}
        EXPORT ravl-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT ravl-targets
        FILE ravl-config.cmake
        NAMESPACE ravl::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ravl
)

if(TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
