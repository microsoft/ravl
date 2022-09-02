
if (OE)
  set(OE_CRYPTO_LIB openssl)

  add_custom_command(
    OUTPUT enclave_t.h enclave_t.c enclave_u.h enclave_u.c enclave_args.h
    DEPENDS ${CMAKE_SOURCE_DIR}/test/oe-enclave/enclave.edl
    COMMAND
      openenclave::oeedger8r
        --trusted ${CMAKE_SOURCE_DIR}/test/oe-enclave/enclave.edl
        --untrusted ${CMAKE_SOURCE_DIR}/test/oe-enclave/enclave.edl
        --search-path ${OE_INCLUDEDIR}
        --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)

  add_executable(oe_enclave enclave.cpp enclave_t.c)
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
    DEPENDS oe_enclave enclave.conf oe_private.pem
    COMMAND openenclave::oesign sign -e $<TARGET_FILE:oe_enclave> -c
            ${CMAKE_CURRENT_SOURCE_DIR}/enclave.conf -k oe_private.pem)

  add_custom_target(sign ALL DEPENDS oe_enclave.signed)

  add_executable(oe_host host.cpp ${CMAKE_CURRENT_BINARY_DIR}/enclave_u.c)
  target_include_directories(oe_host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_BINARY_DIR})
  target_link_libraries(oe_host openenclave::oehost dl)
endif()
