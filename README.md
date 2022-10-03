# RAVL

RAVL is a library of remote attestation verification procedures that enables clients of confidential services to verify the remote attestation of the service. 

Currently supported attestation platforms:
  - Intel SGX ECDSA 
  - AMD SEV/SNP
  - Open Enclave (wrapped Intel SGX ECDSA only)

Basic usage:

```
#include <ravl/ravl.h>

std::string attestation = R"({
  "source": "sgx",
  "evidence": "...",
  "endorsements": "...})";

auto att = parse_attestation(attestation);
std::shared_ptr<ravl::Claims> claims = verify(att);
```

See [`test/unit_test.cpp`](test/unit_tests.cpp) for complete examples of simple invocations.

# Dependencies

For clang++ (our primary toolchain):

```
sudo apt install libstdc++-10-dev
```

For g++, use at least version 11:

```
sudo apt install g++-11
```

Currently, the only supported crypto library is OpenSSL and the default build depends on [libcurl](https://curl.se/libcurl/):

```
sudo apt install libcurl4-openssl-dev libssl-dev
```

Optional:

For the demo enclave in test/intel-enclave: Add Intel APT repo as described in the [SGX Installation Guide](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf)

```
sudo apt-get install libsgx-epid libsgx-quote-ex libsgx-dcap-ql
```

For the Open Enclave SDK demo enclave in test/oe-enclave, see https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_20.04.md

```
sudo apt-get install open-enclave
```


## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
