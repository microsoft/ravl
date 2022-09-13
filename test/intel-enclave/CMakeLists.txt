if (SGXSDK)
  add_custom_command(
    OUTPUT enclave_t.h enclave_t.c enclave_u.h enclave_u.c # enclave_args.h
    DEPENDS ${CMAKE_SOURCE_DIR}/test/intel-enclave/enclave.edl
    COMMAND
    /opt/sgxsdk/bin/x64/sgx_edger8r
        --trusted ${CMAKE_SOURCE_DIR}/test/intel-enclave/enclave.edl
        --untrusted ${CMAKE_SOURCE_DIR}/test/intel-enclave/enclave.edl
        --search-path ${SGXSDK}
        )

  add_executable(intel_enclave enclave.cpp enclave_t.c)
  target_include_directories(intel_enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${SGXSDK} ${SGXSDK}/tlibc)
  target_compile_options(intel_enclave PRIVATE -fPIE)
  target_link_directories(intel_enclave PRIVATE ${SGXSDK}/../lib64)
  target_link_libraries(intel_enclave PUBLIC sgx_trts sgx_tservice sgx_ukey_exchange sgx_tcrypto sgx_tcxx sgx_tstdc)
  target_link_options(intel_enclave PRIVATE
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGXSDK}/../lib64
    -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive
    -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -lcrypto -lsgx_tservice -Wl,--end-group
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic
    -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections
  )

  add_custom_command(
    OUTPUT intel_private.pem intel_public.pem
    COMMAND openssl genrsa -out intel_private.pem -3 3072
    COMMAND openssl rsa -in intel_private.pem -pubout -out intel_public.pem)

  add_custom_command(
    OUTPUT intel_enclave.signed
    DEPENDS intel_enclave enclave.conf intel_private.pem
    COMMAND /opt/sgxsdk/bin/x64/sgx_sign sign -enclave $<TARGET_FILE:intel_enclave> -config
            ${CMAKE_CURRENT_SOURCE_DIR}/enclave.conf -key intel_private.pem -out intel_enclave.signed)

  add_custom_target(intel-sign ALL DEPENDS intel_enclave.signed)

  add_executable(intel_host host.cpp ${CMAKE_CURRENT_BINARY_DIR}/enclave_u.c)
  target_include_directories(intel_host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_BINARY_DIR} ${SGXSDK})
  target_link_libraries(intel_host sgx_urts sgx_quote_ex sgx_dcap_ql crypto)
  target_link_directories(intel_host PRIVATE ${SGXSDK}/../lib64)
endif()