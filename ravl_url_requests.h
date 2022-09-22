// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ravl
{
  typedef size_t URLRequestSetId;

  struct URLResponse
  {
    uint32_t code = 0;
    std::unordered_map<std::string, std::string> headers = {};
    std::string body = "";

    std::vector<uint8_t> get_header_data(
      const std::string& name, bool url_decoded = false) const;

    static std::vector<uint8_t> url_decode(const std::string& in);
  };

  typedef std::vector<URLResponse> Responses;

  struct URLRequest
  {
    URLRequest() {}
    URLRequest(const std::string& url) : url(url) {}

    virtual ~URLRequest()
    {
      // if (t && t->joinable())
      //   t->join();
      t = nullptr;
    }

    std::string url = "";
    std::unordered_map<std::string, std::string> headers = {};
    std::string body = "";
    size_t max_attempts = 5;

    URLResponse response;

    URLResponse execute(bool verbose = false); /// synchronous

    typedef void* Handle;

    Handle start(
      bool verbose = false,
      std::function<void(URLResponse&&)> callback = nullptr);
    bool is_complete() const;
    std::optional<URLResponse> collect();

  protected:
    mutable Handle handle = nullptr;
    std::function<void(URLResponse&&)> callback = nullptr;
    std::shared_ptr<std::thread> t = nullptr;
  };

  class URLRequestTracker
  {
  public:
    URLRequestTracker(bool verbose = false) : verbose(verbose) {}
    virtual ~URLRequestTracker() = default;

    virtual URLRequestSetId submit(
      std::vector<URLRequest>&& rs,
      std::function<void(Responses&&)> callback) = 0;

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

    virtual URLRequestSetId submit(
      std::vector<URLRequest>&& rs,
      std::function<void(Responses&&)> callback) override;

    virtual bool is_complete(const URLRequestSetId& id) const override;

    virtual std::vector<URLResponse> collect(
      const URLRequestSetId& id) override;

  protected:
    std::unordered_map<URLRequestSetId, std::vector<URLRequest>> request_sets;
    std::unordered_map<URLRequestSetId, Responses> response_sets;
  };

  class AsynchronousURLRequestTracker : public URLRequestTracker
  {
  public:
    AsynchronousURLRequestTracker(bool verbose = false);
    virtual ~AsynchronousURLRequestTracker() = default;

    virtual URLRequestSetId submit(
      std::vector<URLRequest>&& rsm,
      std::function<void(Responses&&)> callback) override;

    virtual bool is_complete(const URLRequestSetId& id) const override;

    virtual std::vector<URLResponse> collect(
      const URLRequestSetId& id) override;

    void complete(size_t id, size_t i, URLResponse&& response);

  protected:
    bool verbose = false;
    mutable std::mutex mtx;
    typedef std::unordered_map<URLRequestSetId, std::vector<URLRequest>>
      RequestSets;
    RequestSets request_sets;

    std::unordered_map<URLRequestSetId, Responses> response_sets;
  };
}
