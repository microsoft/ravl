// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl_url_requests.h"

#include <cstring>
#include <emscripten/fetch.h>
#include <new>
#include <stdexcept>
#include <string>
#include <unordered_map>

#define EMSCRIPTEN_FETCH_DONE 4

// Fetch API: https://emscripten.org/docs/api_reference/fetch.html

namespace ravl
{
  std::vector<uint8_t> URLResponse::url_decode(const std::string& in)
  {
    // int outsz = 0;
    // char* decoded = curl_easy_unescape(NULL, in.c_str(), in.size(),
    // &outsz); if (!decoded)
    //   throw std::bad_alloc();
    // std::vector<uint8_t> r = {decoded, decoded + outsz};
    // free(decoded);
    // return r;
    return {};
  }

  std::vector<uint8_t> URLResponse::get_header_data(
    const std::string& name, bool url_decoded) const
  {
    auto hit = headers.find(name);
    if (hit == headers.end())
      throw std::runtime_error("missing response header '" + name + "'");
    // if (url_decoded)
    //   return url_decode(hit->second);
    // else
    return {hit->second.data(), hit->second.data() + hit->second.size()};
  }

  URLResponse URLRequest::execute(bool verbose)
  {
    throw std::runtime_error("synchronous fetch not supported");
  }

  bool is_complete(void* handle)
  {
    if (!handle)
      throw std::runtime_error("missing url handle in is_complete()");

    emscripten_fetch_t* fetch = static_cast<emscripten_fetch_t*>(handle);

    return fetch->readyState == EMSCRIPTEN_FETCH_DONE;
  }

  class FetchTracker : public URLRequestTracker
  {
  public:
    FetchTracker(bool verbose = false) : URLRequestTracker(verbose) {}

    bool poll(
      URLRequestSetId id,
      void* multi,
      std::function<void(URLResponses&&)>& callback)
    {
      // auto consume_msgs = [this, id, multi]() {
      //   struct CURLMsg* m;
      //   do
      //   {
      //     int msgq = 0;
      //     m = curl_multi_info_read(multi, &msgq);
      //     if (m && m->msg == CURLMSG_DONE)
      //     {
      //       size_t i = 0;
      //       auto cc = curl_easy_getinfo(m->easy_handle, CURLINFO_PRIVATE,
      //       &i); if (cc == CURLE_OK)
      //         complete(id, i, m->easy_handle);
      //     }
      //   } while (m);
      // };

      if (!is_complete(id))
      {
        std::lock_guard<std::mutex> guard(mtx);
        // poll?
        //  consume_msgs();
        return true;
      }
      else if (callback)
      {
        std::lock_guard<std::mutex> guard(mtx);

        // consume_msgs();
        auto rsps_it = responses.find(id);
        if (rsps_it == responses.end())
          throw std::runtime_error("could not find url responses");

        URLResponses rs;
        rs.swap(rsps_it->second);
        callback(std::move(rs));
        responses.erase(rsps_it);
        requests.erase(id);
      }

      // curl_multi_cleanup(multi);

      return false;
    }

    URLRequestSetId submit(
      URLRequests&& rs, std::function<void(URLResponses&&)>&& callback)
    {
      std::lock_guard<std::mutex> guard(mtx);

      URLRequestSetId id = requests.size();
      auto [it, ok] = requests.emplace(id, TrackedRequests{std::move(rs)});
      if (!ok)
        throw std::bad_alloc();

      TrackedRequests& reqs = it->second;

      auto [rsps_it, rsps_ok] =
        responses.emplace(id, URLResponses(reqs.requests.size()));
      if (!rsps_ok)
        throw std::bad_alloc();

      for (size_t i = 0; i < reqs.requests.size(); i++)
      {
        auto& request = reqs.requests.at(i);

        printf("Submit   %zu: %s\n", i, request.url.c_str());

        emscripten_fetch_attr_t* attr = new emscripten_fetch_attr_t();
        emscripten_fetch_attr_init(attr);
        strcpy(attr->requestMethod, "GET");
        attr->attributes = EMSCRIPTEN_FETCH_LOAD_TO_MEMORY;

        struct FT
        {
          FetchTracker* tracker = nullptr;
          size_t id = 0;
          size_t i = 0;
        };

        attr->userData = new FT{this, id, i};

        attr->onsuccess = [](struct emscripten_fetch_t* fetch) {
          printf(
            "Finished downloading %llu bytes from URL %s.\n",
            fetch->numBytes,
            fetch->url);

          auto ud = static_cast<FT*>(fetch->userData);
          ud->tracker->complete(ud->id, ud->i, fetch);
          emscripten_fetch_close(fetch);
        };

        attr->onerror = [](emscripten_fetch_t* fetch) {
          printf(
            "Downloading %s failed, HTTP status: %d.\n",
            fetch->url,
            fetch->status);
          emscripten_fetch_close(fetch);
        };

        attr->onprogress = [](emscripten_fetch_t* fetch) {
          if (fetch->totalBytes)
          {
            printf(
              "Downloading %s.. %.2f%% complete.\n",
              fetch->url,
              fetch->dataOffset * 100.0 / fetch->totalBytes);
          }
          else
          {
            printf(
              "Downloading %s.. %lld bytes complete.\n",
              fetch->url,
              fetch->dataOffset + fetch->numBytes);
          }
        };

        reqs.handles.push_back(emscripten_fetch(attr, request.url.c_str()));
      }

      printf("All submissions done.\n");

      return id;
    }

    static bool must_retry(
      emscripten_fetch_t* fetch, URLResponse& response, bool verbose)
    {
      if (fetch->status == 429)
      {
        auto q = response.get_header_data("Retry-After", false);
        long retry_after = std::atoi((char*)q.data());
        if (verbose)
          printf("HTTP 429; RETRY after %lds\n", retry_after);
        std::this_thread::sleep_for(std::chrono::seconds(retry_after));
        response.body = "";
        response.headers.clear();
        response.status = 0;
        return true;
      }
      else
        return false;
    }

    void complete(size_t id, size_t i, emscripten_fetch_t* fetch)
    {
      // Lock held by the monitor thread?

      auto rqit = requests.find(id);
      if (rqit == requests.end())
        return;

      auto& req = rqit->second.requests.at(i);

      auto rsit = responses.find(id);
      if (rsit == responses.end())
        throw std::runtime_error("response set not found");

      if (rsit->second.size() != rqit->second.requests.size())
        rsit->second.resize(rqit->second.requests.size());

      if (i >= rsit->second.size())
        throw std::runtime_error("request index too large");

      URLResponse& response = rsit->second.at(i);

      if (must_retry(fetch, response, true))
      {
        // TODO: requeue
      }
      else
      {
        response.status = fetch->status;
        response.body = {fetch->data, static_cast<size_t>(fetch->numBytes)};
        // TODO
        // emscripten_fetch_get_response_headers_length(fetch);
        // r.headers = {};

        printf(
          "Complete %zu: %u size %zu (req. %zu)\n",
          i,
          response.status,
          response.body.size(),
          id);
      }
    }

    bool is_complete(const URLRequestSetId& id) const
    {
      return false;
    }

  protected:
    mutable std::mutex mtx;

    struct TrackedRequests
    {
      URLRequests requests = {};
      std::vector<emscripten_fetch_t*> handles;
      std::function<void(URLResponses&&)> callback = nullptr;
    };

    typedef std::unordered_map<URLRequestSetId, TrackedRequests> Requests;
    Requests requests;

    std::unordered_map<URLRequestSetId, URLResponses> responses;
  };

  AsynchronousURLRequestTracker::AsynchronousURLRequestTracker(bool verbose)
  {
    implementation = new FetchTracker(verbose);
  }

  AsynchronousURLRequestTracker::~AsynchronousURLRequestTracker()
  {
    delete static_cast<FetchTracker*>(implementation);
  }

  URLRequestSetId AsynchronousURLRequestTracker::submit(
    URLRequests&& rs, std::function<void(URLResponses&&)>&& callback)
  {
    return static_cast<FetchTracker*>(implementation)
      ->submit(std::move(rs), std::move(callback));
  }

  bool AsynchronousURLRequestTracker::is_complete(
    const URLRequestSetId& id) const
  {
    return static_cast<FetchTracker*>(implementation)->is_complete(id);
  }
}
