// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ravl
{
  struct URLResponse
  {
    uint8_t code = 0;
    std::unordered_map<std::string, std::string> headers = {};
    std::string body = "";

    std::vector<uint8_t> get_header_data(
      const std::string& name, bool url_decoded = false) const;

    static std::vector<uint8_t> url_decode(const std::string& in);
  };

  struct URLRequest
  {
    URLRequest() {}
    URLRequest(const std::string& url) : url(url) {}

    std::string url = "";
    std::unordered_map<std::string, std::string> headers = {};
    std::string body = "";

    URLResponse execute(bool verbose = false) const;
  };

  typedef size_t URLRequestSetId;

  class URLRequestTracker
  {
  public:
    URLRequestTracker(bool verbose = false) : verbose(verbose) {}
    virtual ~URLRequestTracker() = default;

    virtual URLRequestSetId submit(std::vector<URLRequest>&& rs) = 0;

    virtual bool is_complete(const URLRequestSetId& id) const = 0;

    virtual std::vector<URLResponse> collect(const URLRequestSetId& id) = 0;

  protected:
    bool verbose = false;
  };

  class SynchronousURLRequestTracker : public URLRequestTracker
  {
  public:
    SynchronousURLRequestTracker(bool verbose = false);
    virtual ~SynchronousURLRequestTracker() = default;

    virtual URLRequestSetId submit(std::vector<URLRequest>&& rs) override;

    virtual bool is_complete(const URLRequestSetId& id) const override;

    virtual std::vector<URLResponse> collect(
      const URLRequestSetId& id) override;

  protected:
    std::unordered_map<URLRequestSetId, std::vector<URLRequest>> request_sets;
    std::unordered_map<URLRequestSetId, std::vector<URLResponse>> response_sets;
  };
}
