# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

function(add_unit_test NAME SRC)
  add_executable(${NAME} ${SRC})
  target_link_libraries(${NAME} PRIVATE $<BUILD_INTERFACE:ravl>)

  if(PROFILE)
    target_compile_options(${NAME} PRIVATE -g -pg)
    target_link_options(${NAME} PRIVATE -g -pg)
  endif()

  if(SAN)
    target_compile_options(
      ${NAME} PRIVATE -fsanitize=undefined,address -fno-omit-frame-pointer
    )
    target_link_options(${NAME} PRIVATE -fsanitize=undefined,address)
  endif()

  add_test(${NAME} ${NAME})
endfunction()

function(add_ravl_test target source)
  add_unit_test(${RAVL_TEST_PREFIX}${target} ${source})
  set_tests_properties(
    ${RAVL_TEST_PREFIX}${target} PROPERTIES LABELS "ravl"
  )
  if (DOCTEST_DIR)
    target_include_directories(
      ${RAVL_TEST_PREFIX}${target} PRIVATE ${DOCTEST_DIR}
    )
  endif()  
  if (WIN32)
    target_compile_definitions(${RAVL_TEST_PREFIX}${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
  endif()
  target_include_directories(
      ${RAVL_TEST_PREFIX}${target} PRIVATE ${RAVL_INCLUDE}
    )
  target_compile_definitions(${RAVL_TEST_PREFIX}${target} PRIVATE ${RAVL_DEFS})
  target_link_libraries(${RAVL_TEST_PREFIX}${target} PRIVATE pthread)
  if(PROFILE)
    target_compile_options(${RAVL_TEST_PREFIX}${target} PRIVATE -g -pg)
    target_link_options(${RAVL_TEST_PREFIX}${target} PRIVATE -g -pg)
  endif()
  if(SAN)
    target_compile_options(
      ${RAVL_TEST_PREFIX}${target} PRIVATE -fsanitize=undefined,address -fno-omit-frame-pointer
    )
    target_link_options(${RAVL_TEST_PREFIX}${target} PRIVATE -fsanitize=undefined,address)
  endif()
endfunction()

find_path(DOCTEST_DIR "doctest.h" PATH 3rdparty/doctest)

if(DOCTEST_DIR)
  add_ravl_test(unit_tests unit_tests.cpp)    
endif()

add_executable(demo demo.cpp)
if(SHARED)
  target_link_libraries(demo ravl-shared)
elseif(STATIC)
  target_link_libraries(demo ravl)
endif()
if(SAN)
  target_link_options(demo PRIVATE -fsanitize=undefined,address)
endif()

add_subdirectory(oe-enclave)
add_subdirectory(intel-enclave)
