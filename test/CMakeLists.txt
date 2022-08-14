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

if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
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
endfunction()

# add_ravl_test(demo_tree demo_tree.cpp)

find_path(DOCTEST_DIR "doctest.h" PATH 3rdparty/doctest)

if(DOCTEST_DIR)
  add_ravl_test(unit_tests unit_tests.cpp)  
endif()

if (OE)
  # find_package(OpenEnclave CONFIG REQUIRED)

  set(OE_CRYPTO_LIB openssl)

  add_custom_command(
  OUTPUT oe_enclave_t.h oe_enclave_t.c oe_enclave_u.h oe_enclave_u.c oe_enclave_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/test/oe_enclave.edl
  COMMAND
    openenclave::oeedger8r 
      --trusted ${CMAKE_SOURCE_DIR}/test/oe_enclave.edl
      --untrusted ${CMAKE_SOURCE_DIR}/test/oe_enclave.edl 
      --search-path ${OE_INCLUDEDIR} 
      --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)

  add_executable(oe_enclave oe_enclave.cpp oe_enclave_t.c)
  target_include_directories(oe_enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
  target_compile_definitions(oe_enclave PUBLIC OE_API_VERSION=2)
  target_link_libraries(
    oe_enclave PUBLIC openenclave::oeenclave openenclave::oecrypto${OE_CRYPTO_LIB} openenclave::oelibcxx)
  
  add_custom_command(
    OUTPUT oe_private.pem oe_public.pem
    COMMAND openssl genrsa -out oe_private.pem -3 3072
    COMMAND openssl rsa -in oe_private.pem -pubout -out oe_public.pem)  
  
  add_custom_command(
    OUTPUT oe_enclave.signed
    DEPENDS oe_enclave oe_enclave.conf oe_private.pem
    COMMAND openenclave::oesign sign -e $<TARGET_FILE:oe_enclave> -c
            ${CMAKE_CURRENT_SOURCE_DIR}/oe_enclave.conf -k oe_private.pem)
                          
  add_custom_target(sign ALL DEPENDS oe_enclave.signed)
   
  add_executable(oe_host oe_host.cpp ${CMAKE_CURRENT_BINARY_DIR}/oe_enclave_u.c)
  target_include_directories(oe_host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../ ${CMAKE_CURRENT_BINARY_DIR})
  target_link_libraries(oe_host openenclave::oehost dl)

endif()
