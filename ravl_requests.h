// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace ravl
{
  struct Response
  {
    uint8_t code = 0;
    std::unordered_map<std::string, std::string> headers = {};
    std::string body = "";

    std::vector<uint8_t> get_header_data(
      const std::string& name, bool url_decoded = false) const;

    static std::vector<uint8_t> url_decode(const std::string& in);
  };

  struct Request
  {
    std::string url = "";
    std::unordered_map<std::string, std::string> headers = {};
    std::string body = "";

    Response operator()() const;
  };
}
