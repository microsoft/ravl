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
    uint32_t status = 0;
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
    virtual ~URLRequest() = default;

    std::string url = "";
    std::unordered_map<std::string, std::string> headers = {};
    std::string body = "";
    size_t max_attempts = 5;

    URLResponse execute(bool verbose = false); /// synchronous
  };

  typedef std::vector<URLRequest> URLRequests;
  typedef std::vector<URLResponse> URLResponses;

  class URLRequestTracker
  {
  public:
    URLRequestTracker(bool verbose = false) : verbose(verbose) {}
    virtual ~URLRequestTracker() = default;

    virtual URLRequestSetId submit(
      URLRequests&& rs, std::function<void(URLResponses&&)>&& callback) = 0;

    virtual bool is_complete(const URLRequestSetId& id) const = 0;

  protected:
    bool verbose = false;
  };

  class SynchronousURLRequestTracker : public URLRequestTracker
  {
  public:
    SynchronousURLRequestTracker(bool verbose = false);
    virtual ~SynchronousURLRequestTracker() = default;

    virtual URLRequestSetId submit(
      URLRequests&& rs,
      std::function<void(URLResponses&&)>&& callback) override;

    virtual bool is_complete(const URLRequestSetId& id) const override;

  protected:
    std::unordered_map<URLRequestSetId, URLRequests> request_sets;
    std::unordered_map<URLRequestSetId, URLResponses> response_sets;
  };

  class AsynchronousURLRequestTracker : public URLRequestTracker
  {
  public:
    AsynchronousURLRequestTracker(bool verbose = false);
    virtual ~AsynchronousURLRequestTracker() = default;

    virtual URLRequestSetId submit(
      URLRequests&& rs,
      std::function<void(URLResponses&&)>&& callback) override;

    virtual bool is_complete(const URLRequestSetId& id) const override;

  protected:
    mutable std::mutex mtx;

    class MonitorThread;

    struct TrackedRequests
    {
      ~TrackedRequests() {}
      URLRequests requests = {};
      void* handle = NULL;
      std::function<void(URLResponses&&)> callback = nullptr;
    };

    typedef std::unordered_map<URLRequestSetId, std::shared_ptr<MonitorThread>>
      MonitorThreads;

    MonitorThreads monitor_threads;

    typedef std::unordered_map<URLRequestSetId, TrackedRequests> Requests;
    Requests requests;

    std::unordered_map<URLRequestSetId, URLResponses> responses;

    void complete(size_t id, size_t i, void* handle);

    bool poll(
      URLRequestSetId id,
      void* multi,
      std::function<void(URLResponses&&)>& callback);
  };
}
