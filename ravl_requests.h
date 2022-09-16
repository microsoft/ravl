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
    Request() {}
    Request(const std::string& url) : url(url) {}

    std::string url = "";
    std::unordered_map<std::string, std::string> headers = {};
    std::string body = "";

    Response execute(bool verbose = false) const;
  };

  class RequestTracker
  {
  public:
    typedef size_t RequestSetId;

    RequestTracker(bool verbose = false) : verbose(verbose) {}
    virtual ~RequestTracker() = default;

    virtual bool when_completed(
      std::vector<Request>&& rs,
      std::function<bool(std::vector<Response>&&)>&& f) = 0;

    virtual void wait(const RequestSetId& id) = 0;

  protected:
    bool verbose = false;
  };

  class SynchronousRequestTracker : public RequestTracker
  {
  public:
    SynchronousRequestTracker(bool verbose = false);
    virtual ~SynchronousRequestTracker() = default;

    virtual bool when_completed(
      std::vector<Request>&& rs,
      std::function<bool(std::vector<Response>&&)>&& f) override;

    virtual void wait(const RequestSetId& id) override;

  protected:
    std::unordered_map<RequestSetId, std::vector<Request>> request_sets;
    std::unordered_map<RequestSetId, std::vector<Response>> response_sets;
  };
}
