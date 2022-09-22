// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl_url_requests.h"

#include <chrono>
#include <stdexcept>
#include <thread>
#include <vector>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ravl
{
  SynchronousURLRequestTracker::SynchronousURLRequestTracker(bool verbose) :
    URLRequestTracker(verbose)
  {}

  URLRequestSetId SynchronousURLRequestTracker::submit(
    std::vector<URLRequest>&& rs, std::function<void(Responses&&)> callback)
  {
    URLRequestSetId id = request_sets.size();

    // Set up
    request_sets.emplace(id, std::move(rs));
    auto [rit, ok] =
      response_sets.emplace(id, std::vector<URLResponse>(rs.size()));

    if (!ok)
      throw std::bad_alloc();

    // Start
    auto rsit = request_sets.find(id);
    for (size_t i = 0; i < rsit->second.size(); i++)
    {
      auto& request = rsit->second.at(i);
      response_sets[id][i] = request.execute(verbose);

      if (response_sets[id][i].code != 200)
        throw std::runtime_error(
          fmt::format("unexpected HTTP status {}", response_sets[id][i].code));
    }

    callback(collect(id));

    return id;
  }

  bool SynchronousURLRequestTracker::is_complete(
    const URLRequestSetId& id) const
  {
    return true;
  }

  std::vector<URLResponse> SynchronousURLRequestTracker::collect(
    const URLRequestSetId& id)
  {
    auto rit = response_sets.find(id);
    if (rit == response_sets.end())
      throw std::runtime_error("no such response set");
    std::vector<URLResponse> r;
    rit->second.swap(r);
    response_sets.erase(rit);
    return r;
  }

  AsynchronousURLRequestTracker::AsynchronousURLRequestTracker(bool verbose) :
    URLRequestTracker(verbose)
  {}

  URLRequestSetId AsynchronousURLRequestTracker::submit(
    std::vector<URLRequest>&& rs, std::function<void(Responses&&)> callback)
  {
    std::lock_guard<std::mutex> guard(mtx);

    URLRequestSetId id = request_sets.size();

    auto [it, ok] = request_sets.emplace(id, std::move(rs));
    if (!ok)
      throw std::bad_alloc();

    auto [rsps_it, rsps_ok] = response_sets.emplace(id, Responses(rs.size()));
    if (!rsps_ok)
      throw std::bad_alloc();

    for (size_t i = 0; i < it->second.size(); i++)
    {
      auto& request = it->second.at(i);
      request.start(verbose, [this, id, i](URLResponse&& response) {
        complete(id, i, std::move(response));
      });
    }

    return id;
  }

  void AsynchronousURLRequestTracker::complete(
    size_t id, size_t i, URLResponse&& response)
  {
    std::lock_guard<std::mutex> guard(mtx);
    auto rit = response_sets.find(id);
    if (rit == response_sets.end())
      throw std::runtime_error("response set not found");
    if (rit->second.size() <= i)
      rit->second.resize(i + 1);
    rit->second[i] = std::move(response);
    // TODO: Notify attestation tracker
  }

  bool AsynchronousURLRequestTracker::is_complete(
    const URLRequestSetId& id) const
  {
    RequestSets::const_iterator rit = request_sets.end();

    {
      std::lock_guard<std::mutex> guard(mtx);
      rit = request_sets.find(id);
      if (rit == request_sets.end())
        throw std::runtime_error("no such request set set");
    }

    for (const auto& r : rit->second)
    {
      if (!r.is_complete())
      {
        printf("not complete: %zu\n", id);
        return false;
      }
    }

    printf("complete\n");

    return true;
  }

  std::vector<URLResponse> AsynchronousURLRequestTracker::collect(
    const URLRequestSetId& id)
  {
    std::vector<URLResponse> responses;

    std::lock_guard<std::mutex> guard(mtx);
    auto rit = request_sets.find(id);
    if (rit == request_sets.end())
      throw std::runtime_error("no such request set set");

    for (size_t i = 0; i < rit->second.size(); i++)
    {
      auto& r = rit->second[i];

      if (!r.is_complete())
        throw std::runtime_error("request not complete");

      auto rsp = r.collect();

      if (!rsp)
        throw std::runtime_error("missing url response");

      responses.emplace_back(std::move(*rsp));
    }

    request_sets.erase(rit);

    return responses;
  }
}